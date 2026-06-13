#![no_std]
#![no_main]

extern crate alloc;

use alloc::boxed::Box;

use ashen_fw::flash_keystore::FlashKeyStore;
use ashen_fw::hw_rng::HwRng;
use ashen_fw::noise_link::{KeyStore, Random, NoiseLink, generate_keypair};
use ashen_fw::protocol::SessionEnd;
use embassy_executor::Spawner;
use embassy_stm32::bind_interrupts;
use embassy_stm32::flash::Flash;
use embassy_stm32::gpio::{Level, Output, Speed};
use embassy_stm32::peripherals::{RNG, USART1};
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

bind_interrupts!(struct Irqs {
    USART1 => embassy_stm32::usart::BufferedInterruptHandler<USART1>;
    RNG => embassy_stm32::rng::InterruptHandler<RNG>;
});

/// Size of the USART1 TX/RX ring buffers.
const UART_BUF_LEN: usize = 256;

/// Blinks the status LED on PA5, independently of the host link.
#[embassy_executor::task]
async fn blink(mut led: Output<'static>) {
    loop {
        led.toggle();
        Timer::after_millis(500).await;
    }
}

/// Returns a fresh, boxed [`HwRng`] backed by the RNG peripheral.
///
/// `rng` is never moved out of `p`; each call clones a fresh handle to the
/// peripheral instead.
///
/// # Safety
///
/// The returned `HwRng` must not be used concurrently with any other handle
/// to the RNG peripheral obtained this way. This holds as long as each
/// returned `Box` is fully consumed (by [`generate_keypair`] or a
/// handshake/restart call) before the next one is created.
unsafe fn boxed_hw_rng(rng: &embassy_stm32::Peri<'static, RNG>) -> Box<dyn Random> {
    Box::new(HwRng::new(Rng::new(unsafe { rng.clone_unchecked() }, Irqs)))
}

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    let p = embassy_stm32::init(Default::default());

    spawner
        .spawn(blink(Output::new(p.PA5, Level::Low, Speed::Low)))
        .expect("failed to spawn blink task");

    let flash = Flash::new_blocking(p.FLASH);
    let mut keystore = FlashKeyStore::new(flash);

    // This boot's ephemeral local keypair.
    // SAFETY: this `HwRng` is fully consumed by `generate_keypair` before
    // any other handle to the RNG peripheral is created.
    let mut local_keys = generate_keypair(unsafe { boxed_hw_rng(&p.RNG) }).expect("local keypair generation failed");

    let mut usart_config = UsartConfig::default();
    usart_config.baudrate = 1_000_000;

    static TX_BUF: StaticCell<[u8; UART_BUF_LEN]> = StaticCell::new();
    static RX_BUF: StaticCell<[u8; UART_BUF_LEN]> = StaticCell::new();
    let uart = BufferedUart::new(
        p.USART1,
        p.PA10,
        p.PA9,
        TX_BUF.init([0; UART_BUF_LEN]),
        RX_BUF.init([0; UART_BUF_LEN]),
        Irqs,
        usart_config,
    )
    .expect("USART1 init failed");

    // SAFETY: see `boxed_hw_rng`; this handle is fully consumed by the
    // handshake before the next one is created in the loop below.
    let handshake_rng = unsafe { boxed_hw_rng(&p.RNG) };
    let link = NoiseLink::responder_handshake(uart, &local_keys.private, handshake_rng, &mut keystore)
        .await
        .expect("handshake failed");

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
            // SAFETY: see `boxed_hw_rng`.
            local_keys = generate_keypair(unsafe { boxed_hw_rng(&p.RNG) })
                .expect("local keypair generation failed");
        }

        // Restart the link with a fresh handshake over the same UART: the
        // peer is expected to reconnect. The slot is briefly empty while the
        // handshake runs (see `panic_link`'s `Option` impl).
        let io = link.take().expect("link present").into_io();
        // SAFETY: see `boxed_hw_rng`.
        let rng = unsafe { boxed_hw_rng(&p.RNG) };
        *link = Some(
            NoiseLink::responder_handshake(io, &local_keys.private, rng, &mut keystore)
                .await
                .expect("handshake failed"),
        );
    }
}
