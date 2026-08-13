//! Plain-text logging over an [`embassy_sync::pipe::Pipe`].
//!
//! Log records are formatted with [`core::fmt`] and written as UTF-8 bytes
//! into a fixed-size byte [`Pipe`]. The pipe is drained by
//! [`NoiseLink::run_session`](crate::noise_link::NoiseLink::run_session), which
//! forwards the bytes to the host as [`Message::Log`](crate::protocol::Message)
//! messages whenever the link isn't otherwise busy.
//!
//! Writing is best-effort and lossy: a record is written with
//! [`Pipe::try_write`], so if the pipe is full the remainder of the record is
//! dropped rather than blocking the firmware. This matters because log records
//! are emitted from arbitrary contexts, including interrupt handlers and the
//! `#[panic_handler]`, where blocking on a consumer is not an option.

use core::fmt::{self, Write};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;

/// Capacity, in bytes, of the log pipe. Records written while the pipe is
/// full are truncated.
pub const LOG_PIPE_CAPACITY: usize = 1024;

/// The byte pipe carrying formatted log records to the host.
///
/// Log records are emitted from interrupt handlers as well as from tasks, so
/// the pipe's internal state is guarded by a critical section. On the firmware
/// the `critical-section` implementation comes from `cortex-m`; host builds
/// pull in `critical-section/std` (see this crate's `Cargo.toml`).
static LOG_PIPE: Pipe<CriticalSectionRawMutex, LOG_PIPE_CAPACITY> = Pipe::new();

/// Severity of a log record, rendered as a prefix on the formatted line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub const fn as_str(self) -> &'static str {
        match self {
            Level::Error => "ERROR",
            Level::Warn => "WARN",
            Level::Info => "INFO",
            Level::Debug => "DEBUG",
            Level::Trace => "TRACE",
        }
    }
}

/// A [`core::fmt::Write`] sink that appends to [`LOG_PIPE`], silently dropping
/// bytes that do not fit. `write_str` still reports success in that case: a
/// full pipe means the host is not keeping up, which is not an error the
/// logging call site can do anything about.
struct PipeWriter;

impl Write for PipeWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut bytes = s.as_bytes();
        while !bytes.is_empty() {
            match LOG_PIPE.try_write(bytes) {
                Ok(n) => bytes = &bytes[n..],
                // Pipe full: drop the rest of this record.
                Err(_) => break,
            }
        }
        Ok(())
    }
}

/// Formats and enqueues one log record, terminated by a newline. Used by the
/// [`error!`](crate::error), [`warn!`](crate::warn), [`info!`](crate::info),
/// [`debug!`](crate::debug) and [`trace!`](crate::trace) macros; prefer those
/// over calling this directly.
pub fn log_record(level: Level, args: fmt::Arguments) {
    let mut writer = PipeWriter;
    let _ = writeln!(writer, "[{}] {}", level.as_str(), args);
}

/// Reads any immediately-available log bytes into `out`, returning `0` if the
/// pipe is empty. Never waits, so this is safe to call both as a cancellable
/// `select` arm and from a `#[panic_handler]` where the executor may no
/// longer be running.
pub fn try_read(out: &mut [u8]) -> usize {
    LOG_PIPE.try_read(out).unwrap_or(0)
}

/// Resolves once at least one log byte is buffered, without consuming it.
///
/// A consuming read would be wrong for a
/// [`select`](embassy_futures::select::select) arm: losing the race drops the
/// future, and any bytes it had already copied out would be lost. A
/// zero-length read resolves as soon as the pipe is non-empty but copies
/// nothing, and registers the read waker while the pipe is empty, so it
/// cannot miss a concurrent write either.
pub async fn wait_readable() {
    LOG_PIPE.read(&mut []).await;
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)*) => {
        $crate::log::log_record($crate::log::Level::Error, ::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)*) => {
        $crate::log::log_record($crate::log::Level::Warn, ::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! info {
    ($($arg:tt)*) => {
        $crate::log::log_record($crate::log::Level::Info, ::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::log::log_record($crate::log::Level::Debug, ::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! trace {
    ($($arg:tt)*) => {
        $crate::log::log_record($crate::log::Level::Trace, ::core::format_args!($($arg)*))
    };
}
