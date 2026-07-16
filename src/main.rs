#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use ashen_fw::flash_keystore::FlashKeyStore;
use ashen_fw::framing::ResetReader;
use ashen_fw::hw_rng::{self, HwRng};
use ashen_fw::noise_link::{KeyStore, Random, NoiseLink, generate_keypair};
use ashen_fw::protocol::SessionEnd;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::{LPUART1, RNG};
use embassy_stm32::rng::Rng;
use embassy_stm32::usart::{BufferedUart, Config as UsartConfig};
use embassy_time::Timer;
use static_cell::StaticCell;

// `ashen_fw::defmt_link` provides the `defmt` global logger, which tees log
// frames to RTT (for probe-rs) and to a queue forwarded over the secure
// Noise channel by `NoiseLink::run_session`.
#[allow(unused_imports)]
use ashen_fw::defmt_link as _;

// The `#[panic_handler]` is provided by `ashen_fw::panic_link`, which makes a
// best-effort attempt to report panics over the secure Noise channel.
#[allow(unused_imports)]
use ashen_fw::panic_link as _;

#[global_allocator]
static ALLOCATOR: emballoc::Allocator<4096> = emballoc::Allocator::new();

// LPUART1 (PG7 TX / PG8 RX) is the internal serial link to the UNO Q's QRB2210
// SoC — the port the SoC-side `arduino-router` (/dev/ttyHS1) talks to. USART1 on
// this board is instead broken out to the Arduino R3 header (D0/D1), so it is
// *not* the host link. See the Zephyr board devicetree for arduino_uno_q.
bind_interrupts!(struct Irqs {
    LPUART1 => embassy_stm32::usart::BufferedInterruptHandler<LPUART1>;
    RNG => embassy_stm32::rng::InterruptHandler<RNG>;
});

/// Size of the LPUART1 TX/RX ring buffers.
const UART_BUF_LEN: usize = 256;

/// Blinks a status LED, independently of the host link.
#[embassy_executor::task]
async fn blink(mut led: Output<'static>) {
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}

/// Returns a fresh, boxed [`HwRng`] handle for the RNG peripheral.
///
/// [`hw_rng::init`] must have installed the driver first. Handles are
/// zero-sized and may be created freely; see [`ashen_fw::hw_rng`].
fn boxed_hw_rng() -> Box<dyn Random> {
    Box::new(HwRng::new())
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Default::default());

    // Status LED: the UNO Q's user RGB LEDs sit on port H and are active-low, so
    // start High (off). PH10 is LED3's red channel per the Zephyr board dts.
    spawner.spawn(
        blink(Output::new(p.PH10, Level::High, Speed::Low)).expect("failed to spawn blink task"),
    );

    // Hand the RNG peripheral to `hw_rng`, which owns it for the rest of the
    // program and hands out `HwRng` handles on demand.
    hw_rng::init(Rng::new(p.RNG, Irqs));

    let flash = Flash::new_blocking(p.FLASH);
    let mut keystore = FlashKeyStore::new(flash);

    // This boot's ephemeral local keypair.
    let mut local_keys = generate_keypair(boxed_hw_rng()).expect("local keypair generation failed");

    let mut usart_config = UsartConfig::default();
    usart_config.baudrate = 1_000_000;

    static TX_BUF: StaticCell<[u8; UART_BUF_LEN]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; UART_BUF_LEN]> = StaticCell::new();
    // LPUART1: rx = PG8, tx = PG7 (BufferedUart::new takes rx before tx).
    let uart = BufferedUart::new(
        p.LPUART1,
        p.PG8,
        p.PG7,
        TX_BUF.init([0; UART_BUF_LEN]),
        RX_BUF.init([0; UART_BUF_LEN]),
        Irqs,
        usart_config,
    )
    .expect("LPUART1 init failed");

    // Wrap the UART so the link-reset detector (a run of >=8 null bytes) and
    // the "ignore all data until the first reset" startup rule persist across
    // every handshake over this UART.
    let io = ResetReader::new(uart);

    let link = NoiseLink::responder_handshake_retry(io, &local_keys.private, boxed_hw_rng, &mut keystore)
        .await;

    // The link lives in an `Option` slot so that, between sessions, it can
    // be taken out (recovering the underlying UART) and replaced with a
    // freshly handshaked link over the same UART.
    static LINK: StaticCell<Option<NoiseLink<BufferedUart<'static>>>> = StaticCell::new();
    let link = LINK.init(Some(link));

    // SAFETY: this creates a second `&'static mut` alias of `link`, used
    // only by the panic handler. The panic handler runs (at most once) only
    // after a panic has permanently halted the rest of the program (see
    // `ashen_fw::panic_link`), at which point the session loop below can no
    // longer be touching `link`, so the two references are never live at
    // the same time.
    let panic_link: &'static mut Option<NoiseLink<BufferedUart<'static>>> =
        unsafe { &mut *(link as *mut _) };
    ashen_fw::panic_link::register(panic_link);

    loop {
        let end = link
            .as_mut()
            .expect("link is always present at the start of a session")
            .run_session(&mut keystore)
            .await;

        if let SessionEnd::Erased = end {
            keystore.erase();
            local_keys = generate_keypair(boxed_hw_rng())
                .expect("local keypair generation failed");
        }

        // Restart the link with a fresh handshake over the same UART: the
        // peer is expected to reconnect. The slot is briefly empty while the
        // handshake runs (see `panic_link`'s `Option` impl).
        let io = link.take().expect("link present").into_io();
        *link = Some(
            NoiseLink::responder_handshake_retry(io, &local_keys.private, boxed_hw_rng, &mut keystore)
                .await,
        );
    }
}
