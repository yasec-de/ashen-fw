//! Tamper input: the demo's "big button" on Arduino D10 (PB9).
//!
//! The button pulls PB9 to GND against an external pull-up. On a confirmed low
//! level, send `Tamper` over the link (the host panics on it at once), wipe all
//! SRAM (TPM seeds and NV, masked key slots, Noise session) and reset. If the
//! message can't go out, the host still notices the missing heartbeat. After
//! the reset the MCU comes back unkeyed of its old TPM state. We never send
//! `Disconnect` here: the host treats that as an orderly shutdown and disarms
//! its heartbeat.

use embassy_stm32::exti::ExtiInput;
use embassy_stm32::mode::Async;
use embassy_time::{Duration, Timer, with_timeout};

use crate::panic_link::{Halt, wipe_and};
use crate::protocol::{TAMPER, TAMPER_SENT};

/// A low level must persist this long to count; filters EMI spikes on the
/// button wire without delaying a real press noticeably.
const CONFIRM: Duration = Duration::from_micros(500);

/// How long the session may take to get `Tamper` out: the frame it may be
/// sending (~1.3 ms at most at 4 MBd) plus ours. Without a session, give up.
const SEND_TIMEOUT: Duration = Duration::from_millis(5);

/// Watch `input` (configured with a pull-up) and trigger the tamper response.
pub async fn monitor(mut input: ExtiInput<'static, Async>) -> ! {
    loop {
        // Level, not edge: also catches a button already held at boot.
        input.wait_for_low().await;
        Timer::after(CONFIRM).await;
        if input.is_low() {
            break;
        }
        crate::warn!("tamper: glitch on D10 ignored");
    }

    TAMPER.signal(());
    let _ = with_timeout(SEND_TIMEOUT, TAMPER_SENT.wait()).await;
    // The send completes when the UART has the last bytes, not when they're
    // on the wire; a few byte times at 4 MBd.
    Timer::after(Duration::from_micros(50)).await;
    wipe_and(Halt::Reset)
}
