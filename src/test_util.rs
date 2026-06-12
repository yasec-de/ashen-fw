//! Shared test-only infrastructure, used by both this crate's unit tests and
//! the host-side integration tests under `tests/`.

use alloc::boxed::Box;
use alloc::vec;

use embedded_io_async::{Read, Write};
use subtle::ConstantTimeEq;

use crate::cobs;
use crate::noise_link::{Error, KeyStore, NoiseLink, Random, builder};

/// A minimal xorshift64* PRNG.
///
/// **Not cryptographically secure.** This exists purely as a deterministic,
/// fast [`Random`] source for tests, so that test runs are fully
/// reproducible. Production code must use a true hardware entropy source
/// (see [`crate::hw_rng`]).
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

/// Performs the initiator side of a Noise_XX handshake (`-> e` then `<- e,
/// ee, s, es` then `-> s, se`) over `io`, checking the responder's static
/// key against `keystore`.
///
/// Returns the resulting transport state, the responder's static key, and
/// whether it was already trusted (`true`) or hasn't been trusted yet
/// (`false`). A previously-trusted key that doesn't match is reported as
/// [`Error::UntrustedPeer`].
///
/// Test-only: the firmware only ever acts as the Noise responder; this side
/// exists purely to drive [`NoiseLink::responder_handshake`]/
/// [`NoiseLink::restart_responder`] from the host-side integration tests.
async fn do_initiator_handshake<T: Read + Write, K: KeyStore>(
    io: &mut T,
    local_static_key: &[u8],
    rng: Box<dyn Random>,
    keystore: &mut K,
) -> Result<(snow::TransportState, [u8; 32], bool), Error> {
    let mut hs = builder(rng)?
        .local_private_key(local_static_key)?
        .build_initiator()?;

    let mut buf = vec![0u8; cobs::MAX_PAYLOAD_LEN + 16];

    // -> e
    let len = hs.write_message(&[], &mut buf)?;
    cobs::write_frame(io, &buf[..len]).await?;

    // <- e, ee, s, es
    let msg = cobs::read_frame(io).await?;
    hs.read_message(&msg, &mut buf)?;

    // -> s, se
    let len = hs.write_message(&[], &mut buf)?;
    cobs::write_frame(io, &buf[..len]).await?;

    let remote_static = hs
        .get_remote_static()
        .expect("XX initiator always learns remote static");
    let mut key = [0u8; 32];
    key.copy_from_slice(remote_static);

    let peer_trusted = match keystore.trusted_key() {
        Some(trusted) if bool::from(trusted.ct_eq(&key)) => true,
        Some(_) => return Err(Error::UntrustedPeer),
        None => false,
    };

    let transport = hs.into_transport_mode()?;
    Ok((transport, key, peer_trusted))
}

/// Test-only initiator-side handshake helpers, mirroring
/// [`NoiseLink::responder_handshake`]/[`NoiseLink::restart_responder`]. The
/// firmware only ever acts as the responder; these are used by the host-side
/// integration tests under `tests/` to simulate the firmware's peer.
impl<T: Read + Write> NoiseLink<T> {
    /// Performs the initiator side of a Noise_XX handshake, verifying the
    /// responder's static key against `keystore` via TOFU.
    pub async fn initiator_handshake<K: KeyStore>(
        mut io: T,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, Error> {
        let (transport, remote_static, peer_trusted) =
            do_initiator_handshake(&mut io, local_static_key, rng, keystore).await?;

        let mut link = Self {
            io,
            transport,
            peer_trusted,
            remote_static,
        };
        if !peer_trusted {
            // First connection: trust-on-first-use.
            link.trust(keystore);
        }
        Ok(link)
    }

    /// Re-runs the initiator handshake on this link's existing transport.
    /// See [`NoiseLink::restart_responder`].
    pub async fn restart_initiator<K: KeyStore>(
        &mut self,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<(), Error> {
        let (transport, remote_static, peer_trusted) =
            do_initiator_handshake(&mut self.io, local_static_key, rng, keystore).await?;

        self.transport = transport;
        self.peer_trusted = peer_trusted;
        self.remote_static = remote_static;
        if !peer_trusted {
            // First connection: trust-on-first-use.
            self.trust(keystore);
        }
        Ok(())
    }
}
