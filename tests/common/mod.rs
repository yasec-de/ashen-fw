//! Shared host-side test infrastructure.

use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Condvar, Mutex};

use ashen_fw::noise_link::SecretKeys;

pub use ashen_fw::test_util::rng;

pub fn secret_keys(identity: &[u8]) -> SecretKeys {
    static INIT: Mutex<()> = Mutex::new(());

    let _guard = INIT.lock().unwrap_or_else(|err| err.into_inner());
    SecretKeys::from_identity(identity)
}

/// A byte-oriented duplex pipe built from two `mpsc` channels, implementing
/// the `embedded-io` traits used by [`SecureLink`].
pub struct ChannelIo {
    tx: Sender<u8>,
    rx: Receiver<u8>,
    gate: Option<Arc<WriteGate>>,
}

#[derive(Default)]
pub struct WriteGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

#[derive(Default)]
struct GateState {
    closed: bool,
    writer_waiting: bool,
}

#[allow(dead_code)]
impl WriteGate {
    pub fn close(&self) {
        self.state.lock().unwrap().closed = true;
    }

    pub fn open(&self) {
        self.state.lock().unwrap().closed = false;
        self.changed.notify_all();
    }

    pub fn wait_for_blocked_writer(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.writer_waiting {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn pass(&self) {
        let mut state = self.state.lock().unwrap();
        while state.closed {
            state.writer_waiting = true;
            self.changed.notify_all();
            state = self.changed.wait(state).unwrap();
        }
        state.writer_waiting = false;
    }
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
    /// Yields instead of blocking when no byte is ready. A blocking `recv()`
    /// here would wedge the whole executor inside one arm of a `select`, which
    /// the firmware's DMA-backed reader never does, and would hide any bug in
    /// code that depends on the other arms making progress.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match self.rx.try_recv() {
                Ok(byte) => {
                    buf[0] = byte;
                    return Ok(1);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => {
                    embassy_futures::yield_now().await;
                }
                Err(std::sync::mpsc::TryRecvError::Disconnected) => return Err(ChannelError),
            }
        }
    }
}

impl embedded_io_async::Write for ChannelIo {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if let Some(gate) = &self.gate {
            gate.pass();
        }
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
    let (a, b, _) = duplex_pair_gated();
    (a, b)
}

pub fn duplex_pair_gated() -> (ChannelIo, ChannelIo, Arc<WriteGate>) {
    let (a_to_b_tx, a_to_b_rx) = channel();
    let (b_to_a_tx, b_to_a_rx) = channel();
    let gate = Arc::new(WriteGate::default());
    (
        ChannelIo {
            tx: a_to_b_tx,
            rx: b_to_a_rx,
            gate: None,
        },
        ChannelIo {
            tx: b_to_a_tx,
            rx: a_to_b_rx,
            gate: Some(gate.clone()),
        },
        gate,
    )
}
