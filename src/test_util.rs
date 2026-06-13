//! Shared test-only infrastructure, used by both this crate's unit tests and
//! the host-side integration tests under `tests/`.

use alloc::boxed::Box;
use alloc::vec;

use embedded_io_async::{Read, Write};

use crate::cobs;
use crate::noise_link::{Error, KeyStore, NoiseLink, Random, builder};
use crate::protocol::{Disconnect, Envelope, Erase, Msg, PairRequest};

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
impl<T: Read + Write> NoiseLink<T> {
    pub async fn initiator_handshake(
        mut io: T,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
    ) -> Result<Self, Error> {
        let mut hs = builder(rng)?
            .local_private_key(local_static_key)?
            .build_initiator()?;

        let mut buf = vec![0u8; cobs::MAX_PAYLOAD_LEN];

        // -> e
        let len = hs.write_message(&[], &mut buf)?;
        cobs::write_frame(&mut io, &buf[..len]).await?;

        // <- e, ee, s, es
        let msg = cobs::read_frame(&mut io).await?;
        hs.read_message(&msg, &mut buf)?;

        // -> s, se
        let len = hs.write_message(&[], &mut buf)?;
        cobs::write_frame(&mut io, &buf[..len]).await?;

        let transport = hs.into_transport_mode()?;
        let link = Self {
            io,
            transport,
            peer_trusted: true,
        };
        Ok(link)
    }

    /// Sends a [`Disconnect`], telling the peer to end the session.
    pub async fn send_disconnect(&mut self) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::Disconnect(Disconnect::default())),
        })
        .await
    }

    /// Sends an [`Erase`], telling the peer to end the session, erase its
    /// TOFU keystore, and regenerate its static identity key.
    pub async fn send_erase(&mut self) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::Erase(Erase::default())),
        })
        .await
    }

    /// Sends a [`PairRequest`], asking the peer to commit our static key to
    /// its keystore (only succeeds while the peer is erased/unkeyed).
    pub async fn send_pair_request(&mut self) -> Result<(), Error> {
        self.send_envelope(&Envelope {
            r#msg: Some(Msg::PairRequest(PairRequest::default())),
        })
        .await
    }
}
