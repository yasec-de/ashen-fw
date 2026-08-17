#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use ashen_fw::flash_keystore::FlashKeyStore;
use ashen_fw::framing::ResetReader;
use ashen_fw::hw_rng::{self, HwRng};
use ashen_fw::noise_link::{KeyStore, NoiseLink, Random, generate_keypair};
use ashen_fw::protocol::SessionEnd;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
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

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<4096> = emballoc::Allocator::new();

bind_interrupts!(struct Irqs {
    LPUART1 => embassy_stm32::usart::InterruptHandler<LPUART1>;
    GPDMA1_CHANNEL1 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH1>;
    GPDMA1_CHANNEL2 => embassy_stm32::dma::InterruptHandler<embassy_stm32::peripherals::GPDMA1_CH2>;
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

        ashen_fw::info!("session end: {:?}", end);

        if let SessionEnd::Erased = end {
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
