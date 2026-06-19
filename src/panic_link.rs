//! Best-effort reporting of firmware panics over the secure Noise channel.
//!
//! Panic handlers run in a broken context with no guarantees about the state
//! of the rest of the program (locks may be held, allocations may fail,
//! peripherals may be mid-transaction). This module lets the application
//! [`register`] a [`NoiseLink`] once its handshake has completed; on panic,
//! the handler logs the panic via `defmt` (queueing a frame in
//! [`crate::defmt_link`]) and makes a best-effort attempt to flush that
//! queue to the host as [`LogMessage`](crate::protocol::LogMessage)
//! envelopes through it before halting. Flushing uses a fixed-size,
//! non-allocating buffer so it cannot itself panic due to allocator failure;
//! if it fails for any other reason (e.g. the transport is wedged, or the
//! panic happened during a send/receive on the same link), the handler gives
//! up silently. Either way, the handler then triggers a `HardFault` via
//! `udf`, the same mechanism `panic-probe` uses, so that `probe-rs`/
//! `probe-run` still recognize the panic and print a backtrace.

use core::cell::RefCell;

use critical_section::Mutex;
use embedded_io_async::{Read, Write as IoWrite};

use crate::noise_link::NoiseLink;

/// Object-safe interface for flushing queued `defmt` log frames over a
/// [`NoiseLink`] of any transport type.
pub trait PanicReport: Send {
    /// Flushes any `defmt` log frames queued by [`crate::defmt_link`]
    /// (including the panic message just logged by the
    /// `#[panic_handler]` in this module) to the host as
    /// [`LogMessage`](crate::protocol::LogMessage) envelopes. Errors are
    /// ignored: this is a best-effort report made from a
    /// `#[panic_handler]`, where there is nothing more to do if it fails.
    ///
    /// Drives the underlying async send to completion with
    /// [`embassy_futures::block_on`], so this must not be called with
    /// interrupts disabled (the transport's async I/O relies on interrupts
    /// to make progress).
    fn flush_log_queue(&mut self);
}

/// Allows registering a slot that is briefly empty while the link is being
/// re-handshaked (see the session loop in `main`). A panic during that
/// window simply produces no report.
impl<T: Read + IoWrite + Send> PanicReport for Option<NoiseLink<T>> {
    fn flush_log_queue(&mut self) {
        if let Some(link) = self {
            let _ = embassy_futures::block_on(NoiseLink::flush_log_queue(link));
        }
    }
}

static PANIC_LINK: Mutex<RefCell<Option<&'static mut dyn PanicReport>>> =
    Mutex::new(RefCell::new(None));

/// Registers `link` as the target for the panic log flush performed by the
/// `#[panic_handler]` in this module.
///
/// `link` must be `'static` (e.g. placed in a [`static_cell::StaticCell`]),
/// since the panic handler may run at any point for the remainder of the
/// program. Calling this again replaces the previously registered link.
pub fn register(link: &'static mut dyn PanicReport) {
    critical_section::with(|cs| {
        *PANIC_LINK.borrow_ref_mut(cs) = Some(link);
    });
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    defmt::error!("panic: {}", defmt::Display2Format(info));

    // Take the link out of `PANIC_LINK` (rather than borrowing it for the
    // duration of the flush) so that interrupts are re-enabled while
    // `flush_log_queue` blocks on the transport's async I/O, which relies on
    // interrupts to make progress.
    let link = critical_section::with(|cs| PANIC_LINK.borrow_ref_mut(cs).take());
    if let Some(link) = link {
        link.flush_log_queue();
    }

    hard_fault();
}

/// Triggers a `HardFault` via the `udf` instruction, the same mechanism used
/// by `panic-probe`'s `hard_fault()`. `probe-rs`/`probe-run` recognize this
/// and print a backtrace from the point of the fault, so this is invoked
/// last, after the best-effort link report above.
fn hard_fault() -> ! {
    // `UsageFault` is enabled on Cortex-M4, so disable it first: otherwise
    // `udf` raises a `UsageFault` instead of the `HardFault` that
    // probe-rs/probe-run look for.
    #[cfg(target_os = "none")]
    {
        const SHCSR: *mut u32 = 0xE000ED24usize as _;
        const USGFAULTENA: u32 = 1 << 18;

        unsafe {
            let shcsr = core::ptr::read_volatile(SHCSR);
            core::ptr::write_volatile(SHCSR, shcsr & !USGFAULTENA);
        }
    }

    loop {
        cortex_m::asm::udf();
    }
}
