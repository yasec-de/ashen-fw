#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use ashen_fw::flash_keystore::FlashKeyStore;
use ashen_fw::framing::ResetReader;
use ashen_fw::hw_rng::{self, HwRng};
use ashen_fw::masked_memory;
use ashen_fw::noise_link::{KeyStore, NoiseLink, Random, SecretKeys};
use ashen_fw::protocol::SessionEnd;
use ashen_fw::tpm;
use embassy_executor::{InterruptExecutor, Spawner};
use embassy_stm32::interrupt;
use embassy_stm32::interrupt::{InterruptExt, Priority};
use embassy_stm32::{Peri, bind_interrupts, peripherals};
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::mode::Async;
use embassy_stm32::peripherals::{LPUART1, RNG};
use embassy_stm32::rng::Rng;
use embassy_stm32::usart::{Config as UsartConfig, RingBufferedUartRx, Uart, UartTx};
use embassy_time::Timer;
use embedded_io_async::{Read, Write};
use static_cell::StaticCell;

#[allow(unused_imports)]
use ashen_fw::panic_link as _;

/// emballoc guards its heap with a spinlock, so it must never be re-entered from
/// an interrupt: the link executor (UART5 IRQ) preempting the thread-mode TPM
/// task mid-allocation would spin on the lock forever. Run every heap operation
/// with interrupts masked instead; they are short.
struct IrqSafeAllocator(emballoc::Allocator<131072>);

unsafe impl core::alloc::GlobalAlloc for IrqSafeAllocator {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        critical_section::with(|_| unsafe { self.0.alloc(layout) })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: core::alloc::Layout) {
        critical_section::with(|_| unsafe { self.0.dealloc(ptr, layout) })
    }
}

#[global_allocator]
static ALLOCATOR: IrqSafeAllocator = IrqSafeAllocator(emballoc::Allocator::new());

bind_interrupts!(struct Irqs {
    LPUART1 => embassy_stm32::usart::InterruptHandler<LPUART1>;
    GPDMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH1>;
    GPDMA1_CHANNEL2 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH2>;
    RNG => embassy_stm32::rng::InterruptHandler<RNG>;
});

/// Size of the LPUART1 DMA RX ring buffer.
const UART_BUF_LEN: usize = 256;

static EXECUTOR_HIGH: InterruptExecutor = InterruptExecutor::new();

#[interrupt]
unsafe fn UART5() {
    unsafe { EXECUTOR_HIGH.on_interrupt() }
}

struct SplitIo {
    rx: RingBufferedUartRx<'static>,
    tx: UartTx<'static, Async>,
}

impl embedded_io_async::ErrorType for SplitIo {
    type Error = embassy_stm32::usart::Error;
}

impl Read for SplitIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        self.rx.read(buf).await
    }
}

impl Write for SplitIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if let Err(e) = self.tx.write(buf).await {
            ashen_fw::warn!("uart wr err {:?}", e);
            return Err(e);
        }
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        self.tx.flush().await
    }
}

#[embassy_executor::task]
async fn blink(mut led: Output<'static>) {
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}

fn boxed_hw_rng() -> Box<dyn Random> {
    Box::new(HwRng::new())
}

#[embassy_executor::task]
async fn session_loop(
    link: &'static mut Option<NoiseLink<&'static mut SplitIo>>,
    mut keystore: FlashKeyStore<'static>,
    keys: SecretKeys,
) {
    loop {
        let end = link
            .as_mut()
            .expect("link is always present at the start of a session")
            .run_session(&mut keystore)
            .await;

        ashen_fw::info!("session end: {:?}", end);

        if let SessionEnd::Erased = end {
            keystore.erase();
            if let Err(e) = tpm::reinit() {
                ashen_fw::warn!("TPM re-manufacture after erase failed: {:?}", e);
            }
        } else {
            tpm::reset_client();
        }

        let io = link.take().expect("link present").into_io();
        *link = Some(
            NoiseLink::responder_handshake_retry(io, keys, boxed_hw_rng, &mut keystore).await,
        );
    }
}

struct LinkPeripherals {
    led: Peri<'static, peripherals::PH10>,
    lpuart: Peri<'static, peripherals::LPUART1>,
    tx_pin: Peri<'static, peripherals::PG8>,
    rx_pin: Peri<'static, peripherals::PG7>,
    dma_tx: Peri<'static, peripherals::GPDMA1_CH1>,
    dma_rx: Peri<'static, peripherals::GPDMA1_CH2>,
    flash: Peri<'static, peripherals::FLASH>,
}

/// Send-safe entry point for [`EXECUTOR_HIGH`]: everything it spawns from here
/// on goes through a local `Spawner`, which has no `Send` bound.
#[embassy_executor::task]
async fn high_prio_init(p: LinkPeripherals) {
    let spawner = unsafe { Spawner::for_current_executor() }.await;
    spawner.spawn(masked_memory::run().expect("failed to spawn remasking task"));
    spawner.spawn(link_bootstrap(p).expect("failed to spawn link bootstrap task"));
}

#[embassy_executor::task]
async fn link_bootstrap(p: LinkPeripherals) {
    let spawner = unsafe { Spawner::for_current_executor() }.await;

    spawner.spawn(
        blink(Output::new(p.led, Level::High, Speed::Low)).expect("failed to spawn blink task"),
    );

    let flash = Flash::new_blocking(p.flash);
    let mut keystore = FlashKeyStore::new(flash);
    let (keys, _local_public) =
        SecretKeys::generate(boxed_hw_rng()).expect("local keypair generation failed");

    let mut usart_config = UsartConfig::default();
    usart_config.baudrate = 4_000_000;
    let uart = Uart::new(
        p.lpuart,
        p.tx_pin,
        p.rx_pin,
        p.dma_tx,
        p.dma_rx,
        Irqs,
        usart_config,
    )
    .expect("LPUART1 init failed");
    let (tx, rx) = uart.split();

    static RX_BUF: StaticCell<[u8; UART_BUF_LEN]> = StaticCell::new();
    let rx = rx.into_ring_buffered(RX_BUF.init([0; UART_BUF_LEN]));

    static IO: StaticCell<SplitIo> = StaticCell::new();
    let io = IO.init(SplitIo { rx, tx });
    io.rx.start_uart();
    let io = ResetReader::new(io);
    let link = NoiseLink::responder_handshake_retry(io, keys, boxed_hw_rng, &mut keystore).await;

    static LINK: StaticCell<Option<NoiseLink<&'static mut SplitIo>>> = StaticCell::new();
    let link = LINK.init(Some(link));

    // SAFETY: this creates a second `&'static mut` alias of `link`, used
    // only by the panic handler.
    let panic_link: &'static mut Option<NoiseLink<&'static mut SplitIo>> =
        unsafe { &mut *(link as *mut _) };
    ashen_fw::panic_link::register(panic_link);

    spawner.spawn(session_loop(link, keystore, keys).expect("failed to spawn session task"));
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let mut config = embassy_stm32::Config::default();
    {
        use embassy_stm32::rcc::*;
        config.rcc.hsi = true;
        config.rcc.pll1 = Some(Pll {
            source: PllSource::HSI,
            prediv: PllPreDiv::DIV1,
            mul: PllMul::MUL20, // 16 MHz * 20 = 320 MHz VCO
            divp: None,
            divq: None,
            divr: Some(PllDiv::DIV2), // 320 MHz / 2 = 160 MHz sysclk
        });
        config.rcc.sys = Sysclk::PLL1_R;
        config.rcc.voltage_range = VoltageScale::RANGE1; // required above 110 MHz
    }
    let p = embassy_stm32::init(config);

    hw_rng::init(Rng::new(p.RNG, Irqs));
    tpm::init().expect("fwTPM initialisation failed");

    spawner.spawn(tpm::task().expect("failed to spawn TPM task"));

    interrupt::UART5.set_priority(Priority::P6);
    let high = EXECUTOR_HIGH.start(interrupt::UART5);
    high.spawn(
        high_prio_init(LinkPeripherals {
            led: p.PH10,
            lpuart: p.LPUART1,
            tx_pin: p.PG8,
            rx_pin: p.PG7,
            dma_tx: p.GPDMA1_CH1,
            dma_rx: p.GPDMA1_CH2,
            flash: p.FLASH,
        })
        .expect("failed to spawn high priority init task"),
    );
}
