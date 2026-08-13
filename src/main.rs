#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use ashen_fw::flash_keystore::FlashKeyStore;
use ashen_fw::framing::ResetReader;
use ashen_fw::hw_rng::{self, HwRng};
use ashen_fw::noise_link::{KeyStore, NoiseLink, Random, generate_keypair};
use ashen_fw::protocol::SessionEnd;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::interrupt::typelevel::{
    GPDMA1_CHANNEL2 as Gpdma1Channel2Interrupt, Handler, LPUART1 as Lpuart1Interrupt,
};
use embassy_stm32::mode::Async;
use embassy_stm32::pac;
use embassy_stm32::peripherals::{LPUART1, RNG};
use embassy_stm32::rng::Rng;
use embassy_stm32::usart::{Config as UsartConfig, RingBufferedUartRx, Uart, UartTx};
use embassy_time::Timer;
use embedded_io_async::{Read, Write};
use static_cell::StaticCell;

#[allow(unused_imports)]
use ashen_fw::defmt_link as _;
#[allow(unused_imports)]
use ashen_fw::panic_link as _;

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<4096> = emballoc::Allocator::new();

/// Register state captured for the first failure which stops UART reception.
///
/// `source` is 1 for a hardware-error ISR and 2 for an error returned by
/// `RingBufferedUartRx::read`. `error` is 1=parity, 2=framing, 3=noise,
/// 4=overrun, 5=buffer-too-long, or 255=an unknown future error variant.
///
/// All remaining fields are raw register values. Do not read LPUART_RDR here:
/// that would mutate the condition we are trying to observe.
#[repr(C)]
pub struct UartFailureSnapshot {
    pub magic: u32,
    pub source: u32,
    pub error: u32,
    pub uart_cr1: u32,
    pub uart_cr2: u32,
    pub uart_cr3: u32,
    pub uart_brr: u32,
    pub uart_isr: u32,
    pub dma_misr: u32,
    pub dma_sr_before: u32,
    pub dma_cr_before: u32,
    pub dma_tr1: u32,
    pub dma_tr2: u32,
    pub dma_br1_before: u32,
    pub dma_sar_before: u32,
    pub dma_dar_before: u32,
    pub dma_tr3: u32,
    pub dma_br2: u32,
    pub dma_llr: u32,
    pub flash_nssr: u32,
    pub rng_cr: u32,
    pub rng_sr: u32,
    pub scb_icsr: u32,
    pub scb_cfsr: u32,
    pub scb_hfsr: u32,
    pub dwt_cyccnt: u32,
    pub nvic_ispr0: u32,
    pub nvic_ispr2: u32,
    pub nvic_iabr0: u32,
    pub nvic_iabr2: u32,
    pub dma_sr_after: u32,
    pub dma_cr_after: u32,
    pub dma_br1_after: u32,
    pub dma_sar_after: u32,
    pub dma_dar_after: u32,
}

const EMPTY_UART_FAILURE_SNAPSHOT: UartFailureSnapshot = UartFailureSnapshot {
    magic: 0,
    source: 0,
    error: 0,
    uart_cr1: 0,
    uart_cr2: 0,
    uart_cr3: 0,
    uart_brr: 0,
    uart_isr: 0,
    dma_misr: 0,
    dma_sr_before: 0,
    dma_cr_before: 0,
    dma_tr1: 0,
    dma_tr2: 0,
    dma_br1_before: 0,
    dma_sar_before: 0,
    dma_dar_before: 0,
    dma_tr3: 0,
    dma_br2: 0,
    dma_llr: 0,
    flash_nssr: 0,
    rng_cr: 0,
    rng_sr: 0,
    scb_icsr: 0,
    scb_cfsr: 0,
    scb_hfsr: 0,
    dwt_cyccnt: 0,
    nvic_ispr0: 0,
    nvic_ispr2: 0,
    nvic_iabr0: 0,
    nvic_iabr2: 0,
    dma_sr_after: 0,
    dma_cr_after: 0,
    dma_br1_after: 0,
    dma_sar_after: 0,
    dma_dar_after: 0,
};

#[unsafe(no_mangle)]
#[used]
pub static mut ASHEN_UART_FAILURE_SNAPSHOT: UartFailureSnapshot = EMPTY_UART_FAILURE_SNAPSHOT;

static UART_FAILURE_CAPTURED: AtomicBool = AtomicBool::new(false);

/// State seen at entry to each GPDMA1 channel 2 IRQ, before Embassy clears any
/// flags or updates its software ring counters.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct GpdmaEvent {
    pub sequence: u32,
    pub dwt_cyccnt: u32,
    pub dma_sr: u32,
    pub dma_cr: u32,
    pub dma_br1: u32,
    pub dma_dar: u32,
    pub dma_llr: u32,
    pub uart_isr: u32,
    pub dma_misr: u32,
}

const EMPTY_GPDMA_EVENT: GpdmaEvent = GpdmaEvent {
    sequence: 0,
    dwt_cyccnt: 0,
    dma_sr: 0,
    dma_cr: 0,
    dma_br1: 0,
    dma_dar: 0,
    dma_llr: 0,
    uart_isr: 0,
    dma_misr: 0,
};

const GPDMA_EVENT_CAPACITY: usize = 64;

#[unsafe(no_mangle)]
#[used]
pub static ASHEN_GPDMA2_EVENT_COUNT: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
#[used]
pub static mut ASHEN_GPDMA2_EVENTS: [GpdmaEvent; GPDMA_EVENT_CAPACITY] =
    [EMPTY_GPDMA_EVENT; GPDMA_EVENT_CAPACITY];

#[inline(always)]
unsafe fn read_u32(address: usize) -> u32 {
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

fn uart_error_code(error: embassy_stm32::usart::Error) -> u32 {
    use embassy_stm32::usart::Error;

    match error {
        Error::Parity => 1,
        Error::Framing => 2,
        Error::Noise => 3,
        Error::Overrun => 4,
        Error::BufferTooLong => 5,
        _ => 255,
    }
}

unsafe fn capture_uart_failure(source: u32, error: u32, uart_isr: u32) {
    const SNAPSHOT_MAGIC: u32 = 0x5545_5252; // "UERR"

    if UART_FAILURE_CAPTURED.swap(true, Ordering::SeqCst) {
        return;
    }

    let dma = pac::GPDMA1.ch(2);
    let mut snapshot = UartFailureSnapshot {
        magic: SNAPSHOT_MAGIC,
        source,
        error,
        uart_cr1: pac::LPUART1.cr1().read().0,
        uart_cr2: pac::LPUART1.cr2().read().0,
        uart_cr3: pac::LPUART1.cr3().read().0,
        uart_brr: pac::LPUART1.brr().read().0,
        uart_isr,
        dma_misr: pac::GPDMA1.misr().read().0,
        dma_sr_before: dma.sr().read().0,
        dma_cr_before: dma.cr().read().0,
        dma_tr1: dma.tr1().read().0,
        dma_tr2: dma.tr2().read().0,
        dma_br1_before: dma.br1().read().0,
        dma_sar_before: dma.sar().read(),
        dma_dar_before: dma.dar().read(),
        dma_tr3: dma.tr3().read().0,
        dma_br2: dma.br2().read().0,
        dma_llr: dma.llr().read().0,
        flash_nssr: pac::FLASH.nssr().read().0,
        rng_cr: pac::RNG.cr().read().0,
        rng_sr: pac::RNG.sr().read().0,
        scb_icsr: unsafe { read_u32(0xe000_ed04) },
        scb_cfsr: unsafe { read_u32(0xe000_ed28) },
        scb_hfsr: unsafe { read_u32(0xe000_ed2c) },
        dwt_cyccnt: unsafe { read_u32(0xe000_1004) },
        nvic_ispr0: unsafe { read_u32(0xe000_e200) },
        nvic_ispr2: unsafe { read_u32(0xe000_e208) },
        nvic_iabr0: unsafe { read_u32(0xe000_e300) },
        nvic_iabr2: unsafe { read_u32(0xe000_e308) },
        dma_sr_after: 0,
        dma_cr_after: 0,
        dma_br1_after: 0,
        dma_sar_after: 0,
        dma_dar_after: 0,
    };

    // For an ISR capture, preserve the state above and then stop an active DMA
    // channel at a transfer boundary. A read-error capture happens after
    // Embassy has already stopped the channel.
    if source == 1 && snapshot.dma_cr_before & 1 != 0 {
        dma.cr().modify(|w| w.set_susp(true));
        for _ in 0..65_536 {
            if dma.sr().read().suspf() {
                break;
            }
            core::hint::spin_loop();
        }
    }

    snapshot.dma_sr_after = dma.sr().read().0;
    snapshot.dma_cr_after = dma.cr().read().0;
    snapshot.dma_br1_after = dma.br1().read().0;
    snapshot.dma_sar_after = dma.sar().read();
    snapshot.dma_dar_after = dma.dar().read();
    unsafe {
        core::ptr::write_volatile(&raw mut ASHEN_UART_FAILURE_SNAPSHOT, snapshot);
    }

    // Stop an attached debugger after the snapshot has been committed.
    ashen_uart_failure_breakpoint();
}

struct UartErrorInterruptHandler;

struct GpdmaRxProbeInterruptHandler;

impl Handler<Gpdma1Channel2Interrupt> for GpdmaRxProbeInterruptHandler {
    unsafe fn on_interrupt() {
        let sequence = ASHEN_GPDMA2_EVENT_COUNT.fetch_add(1, Ordering::SeqCst);
        if (sequence as usize) < GPDMA_EVENT_CAPACITY {
            let dma = pac::GPDMA1.ch(2);
            let event = GpdmaEvent {
                sequence,
                dwt_cyccnt: unsafe { read_u32(0xe000_1004) },
                dma_sr: dma.sr().read().0,
                dma_cr: dma.cr().read().0,
                dma_br1: dma.br1().read().0,
                dma_dar: dma.dar().read(),
                dma_llr: dma.llr().read().0,
                uart_isr: pac::LPUART1.isr().read().0,
                dma_misr: pac::GPDMA1.misr().read().0,
            };
            unsafe {
                core::ptr::write_volatile(
                    (core::ptr::addr_of_mut!(ASHEN_GPDMA2_EVENTS) as *mut GpdmaEvent)
                        .add(sequence as usize),
                    event,
                );
            }
        }
    }
}

impl Handler<Lpuart1Interrupt> for UartErrorInterruptHandler {
    unsafe fn on_interrupt() {
        const USART_ISR_ORE: u32 = 1 << 3;

        let uart_isr = pac::LPUART1.isr().read().0;
        // Startup can legitimately intersect a host reconnect burst and
        // produce a transient framing error. Let Embassy report/recover from
        // those normally; only stop here for the hardware-overrun hypothesis
        // this probe is intended to test.
        if uart_isr & USART_ISR_ORE != 0 {
            unsafe {
                capture_uart_failure(1, 4, uart_isr);
            }
        }
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn ashen_uart_failure_breakpoint() {
    const DHCSR: usize = 0xe000_edf0;
    const DHCSR_C_DEBUGEN: u32 = 1 << 0;

    unsafe {
        core::ptr::read_volatile(&raw const ASHEN_UART_FAILURE_SNAPSHOT.magic);
        // BKPT without an attached debugger would raise a HardFault. Only
        // execute it when the core's halting debug support is enabled.
        if read_u32(DHCSR) & DHCSR_C_DEBUGEN != 0 {
            cortex_m::asm::bkpt();
        }
    }
}

bind_interrupts!(struct Irqs {
    LPUART1 => UartErrorInterruptHandler, embassy_stm32::usart::InterruptHandler<LPUART1>;
    GPDMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH1>;
    GPDMA1_CHANNEL2 => GpdmaRxProbeInterruptHandler, embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH2>;
    RNG => embassy_stm32::rng::InterruptHandler<RNG>;
});

/// Size of the LPUART1 DMA RX ring buffer.
const UART_BUF_LEN: usize = 256;

struct SplitIo {
    rx: RingBufferedUartRx<'static>,
    tx: UartTx<'static, Async>,
}

impl embedded_io_async::ErrorType for SplitIo {
    type Error = embassy_stm32::usart::Error;
}

impl Read for SplitIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        match self.rx.read(buf).await {
            Ok(len) => Ok(len),
            Err(error) => {
                if matches!(error, embassy_stm32::usart::Error::Overrun) {
                    unsafe {
                        capture_uart_failure(
                            2,
                            uart_error_code(error),
                            pac::LPUART1.isr().read().0,
                        );
                    }
                }
                Err(error)
            }
        }
    }
}

impl Write for SplitIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if let Err(e) = self.tx.write(buf).await {
            defmt::warn!("uart wr err {}", e);
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
    spawner.spawn(
        blink(Output::new(p.PH10, Level::High, Speed::Low)).expect("failed to spawn blink task"),
    );

    hw_rng::init(Rng::new(p.RNG, Irqs));

    let flash = Flash::new_blocking(p.FLASH);
    let mut keystore = FlashKeyStore::new(flash);
    let local_keys = generate_keypair(boxed_hw_rng()).expect("local keypair generation failed");

    let mut usart_config = UsartConfig::default();
    usart_config.baudrate = 1_000_000;
    let uart = Uart::new(
        p.LPUART1,
        p.PG8,
        p.PG7,
        p.GPDMA1_CH1,
        p.GPDMA1_CH2,
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
    let link =
        NoiseLink::responder_handshake_retry(io, &local_keys.private, boxed_hw_rng, &mut keystore)
            .await;

    static LINK: StaticCell<Option<NoiseLink<&'static mut SplitIo>>> = StaticCell::new();
    let link = LINK.init(Some(link));

    // SAFETY: this creates a second `&'static mut` alias of `link`, used
    // only by the panic handler.
    let panic_link: &'static mut Option<NoiseLink<&'static mut SplitIo>> =
        unsafe { &mut *(link as *mut _) };
    ashen_fw::panic_link::register(panic_link);

    loop {
        let end = link
            .as_mut()
            .expect("link is always present at the start of a session")
            .run_session(&mut keystore)
            .await;

        defmt::info!("session end: {}", defmt::Debug2Format(&end));

        if let SessionEnd::Erased = end {
            // Discard boot/initial-handshake DMA events. The diagnostic log
            // should cover only the erase followed by the next handshake.
            ASHEN_GPDMA2_EVENT_COUNT.store(0, Ordering::SeqCst);
            keystore.erase();
        }

        let io = link.take().expect("link present").into_io();
        *link = Some(
            NoiseLink::responder_handshake_retry(
                io,
                &local_keys.private,
                boxed_hw_rng,
                &mut keystore,
            )
            .await,
        );
    }
}
