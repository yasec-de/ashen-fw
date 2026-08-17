use core::fmt::{self, Write};

use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::pipe::Pipe;

pub const LOG_PIPE_CAPACITY: usize = 1024;

static LOG_PIPE: Pipe<CriticalSectionRawMutex, LOG_PIPE_CAPACITY> = Pipe::new();

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

pub fn log_record(level: Level, args: fmt::Arguments) {
    let mut writer = PipeWriter;
    let _ = writeln!(writer, "[{}] {}", level.as_str(), args);
}

pub fn try_read(out: &mut [u8]) -> usize {
    LOG_PIPE.try_read(out).unwrap_or(0)
}

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
