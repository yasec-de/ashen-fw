//! Shared host-side test infrastructure.

use std::sync::mpsc::{Receiver, Sender, channel};

use ashen_fw::noise_link::Random;

/// A minimal xorshift64* PRNG.
///
/// **Not cryptographically secure.** This exists purely as a deterministic,
/// fast [`Random`] source for tests, so that test runs are fully
/// reproducible. Production code must use a true hardware entropy source
/// (see `ashen_fw::hw_rng`).
#[derive(Clone)]
pub struct XorShiftRng(u64);

impl XorShiftRng {
    pub fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

impl Random for XorShiftRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        for chunk in dest.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
        Ok(())
    }
}

/// Returns a fresh, boxed [`XorShiftRng`] seeded with `seed`.
pub fn rng(seed: u64) -> Box<dyn Random> {
    Box::new(XorShiftRng::new(seed))
}

/// A byte-oriented duplex pipe built from two `mpsc` channels, implementing
/// the `embedded-io` traits used by [`SecureLink`].
pub struct ChannelIo {
    tx: Sender<u8>,
    rx: Receiver<u8>,
}

#[derive(Debug)]
pub struct ChannelError;

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
