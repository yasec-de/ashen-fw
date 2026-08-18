//! Shared test-only infrastructure, used by both this crate's unit tests and
//! the host-side integration tests under `tests/`.

use alloc::boxed::Box;
use alloc::vec;

use embedded_io_async::{Read, Write};

use crate::framing::{self, ResetReader};
use crate::noise_link::{Error, KeyStore, NoiseLink, Random, SecretKeys, builder};
use crate::protocol::Message;

/// PRNG for providing deterministic randomness during tests
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

/// A simple in-memory [`KeyStore`], for tests.
#[derive(Default)]
pub struct TestKeyStore(Option<[u8; 32]>);

impl KeyStore for TestKeyStore {
    fn trusted_key(&self) -> Option<[u8; 32]> {
        self.0
    }

    fn trust(&mut self, key: [u8; 32]) {
        self.0 = Some(key);
    }

    fn erase(&mut self) {
        self.0 = None;
    }
}

/// Initiator-side handshake code mirroring [`NoiseLink::responder_handshake`] for integration tests.
#[cfg(any(test, feature = "test-util"))]
impl<T: Read + Write> NoiseLink<T> {
    pub async fn initiator_handshake(
        io: T,
        keys: SecretKeys,
        rng: Box<dyn Random>,
    ) -> Result<Self, Error> {
        let mut io = ResetReader::new(io);

        // Reset the responder (it ignores all data until reset once) and
        // consume its null reply before starting the handshake.
        io.send_reset().await?;

        let mut hs = {
            let identity = keys.identity.borrow();
            builder(rng, keys)?
                .local_private_key(&identity[..])?
                .build_initiator()?
        };

        let mut buf = vec![0u8; framing::MAX_PAYLOAD_LEN];

        // -> e
        let len = hs.write_message(&[], &mut buf)?;
        framing::write_frame(&mut io, &buf[..len]).await?;

        // <- e, ee, s, es
        let msg = framing::read_frame(&mut io).await?;
        hs.read_message(&msg, &mut buf)?;

        // -> s, se
        let len = hs.write_message(&[], &mut buf)?;
        framing::write_frame(&mut io, &buf[..len]).await?;

        let transport = hs.into_transport_mode()?;
        let link = Self {
            io,
            transport,
            peer_trusted: true,
        };
        Ok(link)
    }

    /// Sends a [`Message::Disconnect`], telling the peer to end the session.
    pub async fn send_disconnect(&mut self) -> Result<(), Error> {
        self.send_msg(&Message::Disconnect).await
    }

    /// Sends a [`Message::Erase`], telling the peer to end the session, erase
    /// its TOFU keystore, and regenerate its static identity key.
    pub async fn send_erase(&mut self) -> Result<(), Error> {
        self.send_msg(&Message::Erase).await
    }

    /// Sends a [`Message::PairRequest`], asking the peer to commit our static
    /// key to its keystore (only succeeds while the peer is erased/unkeyed).
    pub async fn send_pair_request(&mut self) -> Result<(), Error> {
        self.send_msg(&Message::PairRequest).await
    }
}
