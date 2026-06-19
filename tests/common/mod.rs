//! Shared host-side test infrastructure.

use std::sync::mpsc::{Receiver, Sender, channel};

pub use ashen_fw::test_util::rng;

/// A byte-oriented duplex pipe built from two `mpsc` channels, implementing
/// the `embedded-io` traits used by [`SecureLink`].
pub struct ChannelIo {
    tx: Sender<u8>,
    rx: Receiver<u8>,
}

#[derive(Debug)]
pub struct ChannelError;

impl std::fmt::Display for ChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel I/O error")
    }
}

// embedded-io 0.7 requires `Error` types to also implement
// `core::error::Error` (hence `Display`).
impl std::error::Error for ChannelError {}

impl embedded_io::Error for ChannelError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::Other
    }
}

impl embedded_io::ErrorType for ChannelIo {
    type Error = ChannelError;
}

impl embedded_io_async::Read for ChannelIo {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.rx.recv() {
            Ok(byte) => {
                buf[0] = byte;
                Ok(1)
            }
            Err(_) => Err(ChannelError),
        }
    }
}

impl embedded_io_async::Write for ChannelIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        for &byte in buf {
            self.tx.send(byte).map_err(|_| ChannelError)?;
        }
        Ok(buf.len())
    }

    async fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

/// Returns a pair of connected [`ChannelIo`] endpoints.
pub fn duplex_pair() -> (ChannelIo, ChannelIo) {
    let (a_to_b_tx, a_to_b_rx) = channel();
    let (b_to_a_tx, b_to_a_rx) = channel();
    (
        ChannelIo {
            tx: a_to_b_tx,
            rx: b_to_a_rx,
        },
        ChannelIo {
            tx: b_to_a_tx,
            rx: a_to_b_rx,
        },
    )
}
