//! Tamper input: the demo's "big button" on Arduino D10 (PB9).
//!
//! The button pulls PB9 to GND against an external pull-up. On a confirmed low
//! level, log the event over the link, wipe all SRAM (TPM seeds and NV, masked
//! key slots, Noise session) and reset. The host notices the missing heartbeat
//! and runs its own alarm path; after the reset the MCU comes back unkeyed of
//! its old TPM state. We never send `Disconnect` here: the host treats that as
//! an orderly shutdown and disarms its heartbeat.

use embassy_stm32::exti::ExtiInput;
use embassy_stm32::mode::Async;
use embassy_time::{Duration, Timer};

use crate::panic_link::{Halt, flush_wipe_and};

/// A low level must persist this long to count; filters EMI spikes on the
/// button wire without delaying a real press noticeably.
const CONFIRM: Duration = Duration::from_micros(500);

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

    crate::error!("TAMPER: D10 triggered, wiping TPM and keys, resetting");
    flush_wipe_and(Halt::Reset)
}
