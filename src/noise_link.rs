//! Secure transport: Noise_XX over COBS-framed bytes (e.g. a USART link),
//! with trust-on-first-use (TOFU) verification of the remote static key.
//!
//! Wire framing: each message is encoded with [`crate::cobs`] and terminated
//! by a `0x00` delimiter byte, so frames may be of any length up to
//! [`MAX_PAYLOAD_LEN`]. If a frame is malformed (bad COBS encoding or larger
//! than expected), the implementation resynchronizes by discarding bytes up
//! to the next `0x00` delimiter and continues with the following frame.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;

use embedded_io_async::{Read, Write};
use subtle::ConstantTimeEq;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash};
pub use snow::types::Random;
use snow::{Builder, TransportState};

use crate::cobs;

/// Noise handshake pattern used for this link.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Maximum number of plaintext payload bytes carried by a single
/// [`SecureLink::send`]/[`SecureLink::receive`] call.
pub const MAX_PAYLOAD_LEN: usize = 1024;

/// Maximum size (in bytes) of a COBS-encoded frame (including the Noise
/// authentication tag, but excluding the trailing `0x00` delimiter) that
/// [`read_frame`] will accept before giving up and resynchronizing.
const MAX_FRAME_LEN: usize = MAX_PAYLOAD_LEN + 16 + (MAX_PAYLOAD_LEN + 16) / 254 + 2;

/// Errors that can occur while operating a [`SecureLink`].
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// The underlying transport failed.
    Io,
    /// A frame could not be decoded (bad COBS framing or oversized payload).
    Framing,
    /// A payload was too large to fit in a single frame.
    PayloadTooLarge,
    /// The Noise protocol returned an error (handshake or crypto failure).
    Crypto,
    /// The remote static key did not match the previously trusted key.
    UntrustedPeer,
}

impl Error {
    /// A short, human-readable description of this error, prefixed with a
    /// broad category (e.g. `"io: framing error"`), for use with defmt
    /// logging.
    pub fn message(&self) -> &'static str {
        match self {
            Error::Io => "io: transport error",
            Error::Framing => "io: framing error",
            Error::PayloadTooLarge => "io: payload too large",
            Error::Crypto => "crypto: noise protocol error",
            Error::UntrustedPeer => "crypto: untrusted peer",
        }
    }
}

impl From<snow::Error> for Error {
    fn from(_: snow::Error) -> Self {
        Error::Crypto
    }
}

/// Storage for the trust-on-first-use remote static public key.
///
/// On the first successful handshake, the remote's static public key is
/// recorded via [`KeyStore::trust`]. On subsequent handshakes, the
/// presented key is compared against the stored one; a mismatch is
/// reported as [`Error::UntrustedPeer`].
pub trait KeyStore {
    /// Returns the previously trusted remote static key, if any.
    fn trusted_key(&self) -> Option<[u8; 32]>;
    /// Records `key` as the trusted remote static key.
    fn trust(&mut self, key: [u8; 32]);
}

/// A simple in-memory [`KeyStore`].
///
/// Useful for tests, or as a starting point for an embedded implementation
/// that persists the key to flash.
#[derive(Default)]
pub struct MemoryKeyStore(Option<[u8; 32]>);

impl KeyStore for MemoryKeyStore {
    fn trusted_key(&self) -> Option<[u8; 32]> {
        self.0
    }

    fn trust(&mut self, key: [u8; 32]) {
        self.0 = Some(key);
    }
}

/// A [`snow::resolvers::CryptoResolver`] that delegates DH/hash/cipher
/// primitives to [`DefaultResolver`], but uses a caller-supplied [`Random`]
/// implementation as the RNG.
///
/// The supplied RNG is consumed by the first call to
/// [`resolve_rng`](CryptoResolver::resolve_rng) (the only call snow makes per
/// handshake or keypair generation).
struct EmbeddedResolver {
    rng: RefCell<Option<Box<dyn Random>>>,
    inner: DefaultResolver,
}

impl EmbeddedResolver {
    fn new(rng: Box<dyn Random>) -> Self {
        Self {
            rng: RefCell::new(Some(rng)),
            inner: DefaultResolver,
        }
    }
}

impl CryptoResolver for EmbeddedResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.rng.borrow_mut().take()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.inner.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.inner.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        self.inner.resolve_cipher(choice)
    }
}

fn builder(rng: Box<dyn Random>) -> Result<Builder<'static>, Error> {
    let params = NOISE_PATTERN.parse().map_err(|_| Error::Crypto)?;
    Ok(Builder::with_resolver(
        params,
        Box::new(EmbeddedResolver::new(rng)),
    ))
}

/// Generates a new static Curve25519 keypair for use with
/// [`SecureLink::responder_handshake`] or [`SecureLink::initiator_handshake`].
pub fn generate_keypair(rng: Box<dyn Random>) -> Result<snow::Keypair, Error> {
    Ok(builder(rng)?.generate_keypair()?)
}

/// COBS-encodes `payload` and writes it followed by the `0x00` delimiter.
async fn write_frame<T: Write>(io: &mut T, payload: &[u8]) -> Result<(), Error> {
    let mut frame = cobs::encode(payload);
    frame.push(0x00);
    io.write_all(&frame).await.map_err(|_| Error::Io)
}

/// Reads bytes up to the next `0x00` delimiter and COBS-decodes them.
///
/// If the frame is malformed or exceeds [`MAX_FRAME_LEN`], bytes are still
/// consumed up to (and including) the delimiter before returning
/// [`Error::Framing`], so the next call starts cleanly at the following
/// frame.
async fn read_frame<T: Read>(io: &mut T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut overflow = false;
    loop {
        let mut byte = [0u8; 1];
        io.read_exact(&mut byte).await.map_err(|_| Error::Io)?;
        if byte[0] == 0x00 {
            break;
        }
        if buf.len() < MAX_FRAME_LEN {
            buf.push(byte[0]);
        } else {
            overflow = true;
        }
    }
    if overflow {
        return Err(Error::Framing);
    }
    cobs::decode(&buf).map_err(|_| Error::Framing)
}

/// Performs the responder side of a Noise_XX handshake (`<- e, ee, s, es`
/// then `-> s, se`) over `io`, verifying the initiator's static key against
/// `keystore` via TOFU.
///
/// Returns the resulting [`TransportState`], the verified remote static key,
/// and whether it was newly trusted (see [`verify_remote_static`]).
async fn do_responder_handshake<T: Read + Write, K: KeyStore>(
    io: &mut T,
    local_static_key: &[u8],
    rng: Box<dyn Random>,
    keystore: &mut K,
) -> Result<(TransportState, [u8; 32], bool), Error> {
    let mut hs = builder(rng)?
        .local_private_key(local_static_key)?
        .build_responder()?;

    let mut buf = vec![0u8; MAX_PAYLOAD_LEN + 16];

    // -> e
    let msg = read_frame(io).await?;
    hs.read_message(&msg, &mut buf)?;

    // <- e, ee, s, es
    let len = hs.write_message(&[], &mut buf)?;
    write_frame(io, &buf[..len]).await?;

    // -> s, se
    let msg = read_frame(io).await?;
    hs.read_message(&msg, &mut buf)?;

    let (remote_static, newly_trusted) = verify_remote_static(&hs, keystore)?;
    let transport = hs.into_transport_mode()?;
    Ok((transport, remote_static, newly_trusted))
}

/// Performs the initiator side of a Noise_XX handshake (`-> e` then `<- e,
/// ee, s, es` then `-> s, se`) over `io`, verifying the responder's static
/// key against `keystore` via TOFU.
///
/// Returns the resulting [`TransportState`], the verified remote static key,
/// and whether it was newly trusted (see [`verify_remote_static`]).
async fn do_initiator_handshake<T: Read + Write, K: KeyStore>(
    io: &mut T,
    local_static_key: &[u8],
    rng: Box<dyn Random>,
    keystore: &mut K,
) -> Result<(TransportState, [u8; 32], bool), Error> {
    let mut hs = builder(rng)?
        .local_private_key(local_static_key)?
        .build_initiator()?;

    let mut buf = vec![0u8; MAX_PAYLOAD_LEN + 16];

    // -> e
    let len = hs.write_message(&[], &mut buf)?;
    write_frame(io, &buf[..len]).await?;

    // <- e, ee, s, es
    let msg = read_frame(io).await?;
    hs.read_message(&msg, &mut buf)?;

    // -> s, se
    let len = hs.write_message(&[], &mut buf)?;
    write_frame(io, &buf[..len]).await?;

    let (remote_static, newly_trusted) = verify_remote_static(&hs, keystore)?;
    let transport = hs.into_transport_mode()?;
    Ok((transport, remote_static, newly_trusted))
}

/// Logs the outcome of TOFU remote static key verification via `defmt`.
/// Forwarded to the host as a [`crate::protocol::LogMessage`] like any other
/// log frame.
#[cfg(target_os = "none")]
fn log_tofu_status(newly_trusted: bool) {
    if newly_trusted {
        defmt::info!("TOFU: trusted new remote static key");
    } else {
        defmt::info!("TOFU: remote static key validated");
    }
}

#[cfg(not(target_os = "none"))]
fn log_tofu_status(_newly_trusted: bool) {}

/// A handshake-completed Noise_XX link over a COBS-framed byte transport.
///
/// Both sides of the link use the same API after the handshake: call
/// [`SecureLink::send`]/[`SecureLink::receive`] (or
/// [`SecureLink::request`]) to exchange authenticated, encrypted messages,
/// or [`SecureLink::run_session`] to handle a full
/// [`crate::protocol`] session.
///
/// If [`SecureLink::run_session`] ends (the peer disconnected, or an error
/// occurred), the link can be put back into a working state without
/// reallocating the underlying transport by calling
/// [`SecureLink::restart_responder`] or [`SecureLink::restart_initiator`].
pub struct SecureLink<T> {
    io: T,
    transport: TransportState,
    /// The remote party's static public key, as verified by TOFU.
    pub remote_static: [u8; 32],
}

impl<T: Read + Write> SecureLink<T> {
    /// Performs the responder side of a Noise_XX handshake (`<- e, ee, s,
    /// es` then `-> s, se`), verifying the initiator's static key against
    /// `keystore` via TOFU.
    pub async fn responder_handshake<K: KeyStore>(
        mut io: T,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, Error> {
        let (transport, remote_static, newly_trusted) =
            do_responder_handshake(&mut io, local_static_key, rng, keystore).await?;

        let link = Self {
            io,
            transport,
            remote_static,
        };
        log_tofu_status(newly_trusted);
        Ok(link)
    }

    /// Performs the initiator side of a Noise_XX handshake (`-> e` then `<-
    /// e, ee, s, es` then `-> s, se`), verifying the responder's static key
    /// against `keystore` via TOFU.
    pub async fn initiator_handshake<K: KeyStore>(
        mut io: T,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, Error> {
        let (transport, remote_static, newly_trusted) =
            do_initiator_handshake(&mut io, local_static_key, rng, keystore).await?;

        let link = Self {
            io,
            transport,
            remote_static,
        };
        log_tofu_status(newly_trusted);
        Ok(link)
    }

    /// Re-runs the responder handshake on this link's existing transport,
    /// replacing its transport state and [`SecureLink::remote_static`] in
    /// place.
    ///
    /// Used to restart a session (after [`SecureLink::run_session`] returns
    /// due to a disconnect or error) without losing the link's `'static`
    /// identity, e.g. a [`crate::panic_link`] registration pointing at this
    /// link remains valid.
    pub async fn restart_responder<K: KeyStore>(
        &mut self,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<(), Error> {
        let (transport, remote_static, newly_trusted) =
            do_responder_handshake(&mut self.io, local_static_key, rng, keystore).await?;
        self.transport = transport;
        self.remote_static = remote_static;
        log_tofu_status(newly_trusted);
        Ok(())
    }

    /// Re-runs the initiator handshake on this link's existing transport,
    /// replacing its transport state and [`SecureLink::remote_static`] in
    /// place. See [`SecureLink::restart_responder`].
    pub async fn restart_initiator<K: KeyStore>(
        &mut self,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<(), Error> {
        let (transport, remote_static, newly_trusted) =
            do_initiator_handshake(&mut self.io, local_static_key, rng, keystore).await?;
        self.transport = transport;
        self.remote_static = remote_static;
        log_tofu_status(newly_trusted);
        Ok(())
    }

    /// Encrypts and sends `payload` as a single transport message.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::PayloadTooLarge);
        }
        let mut cipher = vec![0u8; payload.len() + 16];
        let len = self.transport.write_message(payload, &mut cipher)?;
        write_frame(&mut self.io, &cipher[..len]).await
    }

    /// Receives and decrypts a single transport message.
    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let msg = read_frame(&mut self.io).await?;
        let mut plain = vec![0u8; msg.len()];
        let len = self.transport.read_message(&msg, &mut plain)?;
        plain.truncate(len);
        Ok(plain)
    }

    /// Sends `request` and returns the corresponding response.
    pub async fn request(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.send(request).await?;
        self.receive().await
    }
}

/// Verifies the handshake's remote static key against `keystore` via TOFU.
///
/// Returns the remote static key, and whether it was newly trusted (i.e.
/// this is the first time this peer has connected) as opposed to matching a
/// previously trusted key.
fn verify_remote_static<K: KeyStore>(
    hs: &snow::HandshakeState,
    keystore: &mut K,
) -> Result<([u8; 32], bool), Error> {
    let remote_static = hs.get_remote_static().ok_or(Error::Crypto)?;
    let mut key = [0u8; 32];
    key.copy_from_slice(remote_static);

    let newly_trusted = match keystore.trusted_key() {
        Some(trusted) if trusted.ct_eq(&key).into() => false,
        Some(_) => return Err(Error::UntrustedPeer),
        None => {
            keystore.trust(key);
            true
        }
    };

    Ok((key, newly_trusted))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal xorshift64* PRNG.
    ///
    /// **Not cryptographically secure.** This exists purely as a
    /// deterministic, fast [`Random`] source for unit tests, so that test
    /// runs are fully reproducible. Production code must use a true
    /// hardware entropy source (see [`crate::hw_rng`]).
    #[derive(Clone)]
    struct XorShiftRng(u64);

    impl XorShiftRng {
        fn new(seed: u64) -> Self {
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

    /// Fixed seed used by all unit tests, so that test runs are
    /// deterministic and reproducible.
    const TEST_RNG_SEED: u64 = 0x1234_5678_9ABC_DEF0;

    /// Returns a fresh [`XorShiftRng`] seeded with [`TEST_RNG_SEED`].
    fn test_rng() -> Box<dyn Random> {
        Box::new(XorShiftRng::new(TEST_RNG_SEED))
    }

    #[test]
    fn keypair_generation_is_deterministic_for_fixed_seed() {
        let a = generate_keypair(test_rng()).unwrap();
        let b = generate_keypair(test_rng()).unwrap();
        assert_eq!(a.private, b.private);
        assert_eq!(a.public, b.public);
    }

    /// An in-memory byte source/sink for testing [`read_frame`]/[`write_frame`].
    struct SliceIo {
        data: Vec<u8>,
        pos: usize,
        out: Vec<u8>,
    }

    impl SliceIo {
        fn new(data: Vec<u8>) -> Self {
            Self {
                data,
                pos: 0,
                out: Vec::new(),
            }
        }
    }

    #[derive(Debug)]
    struct SliceError;

    impl embedded_io::Error for SliceError {
        fn kind(&self) -> embedded_io::ErrorKind {
            embedded_io::ErrorKind::Other
        }
    }

    impl embedded_io::ErrorType for SliceIo {
        type Error = SliceError;
    }

    impl Read for SliceIo {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
            if self.pos >= self.data.len() {
                return Err(SliceError);
            }
            buf[0] = self.data[self.pos];
            self.pos += 1;
            Ok(1)
        }
    }

    impl Write for SliceIo {
        async fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
            self.out.extend_from_slice(buf);
            Ok(buf.len())
        }

        async fn flush(&mut self) -> Result<(), Self::Error> {
            Ok(())
        }
    }

    #[test]
    fn frame_round_trip() {
        embassy_futures::block_on(async {
            let mut io = SliceIo::new(Vec::new());
            write_frame(&mut io, b"hello world").await.unwrap();

            let mut reader = SliceIo::new(io.out);
            let frame = read_frame(&mut reader).await.unwrap();
            assert_eq!(frame, b"hello world");
        });
    }

    #[test]
    fn resync_after_corrupt_frame() {
        embassy_futures::block_on(async {
            // A corrupt frame (a code byte claiming more data than follows,
            // which is invalid COBS) followed by the delimiter, then a valid
            // frame.
            let mut data = vec![0x05, 0x00];
            let mut good = cobs::encode(b"second frame");
            good.push(0x00);
            data.append(&mut good);

            let mut io = SliceIo::new(data);

            // First frame is corrupt.
            assert!(matches!(read_frame(&mut io).await, Err(Error::Framing)));

            // Reader has resynchronized and can decode the next frame.
            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"second frame");
        });
    }

    #[test]
    fn resync_after_oversized_frame() {
        embassy_futures::block_on(async {
            // A frame longer than MAX_FRAME_LEN (no zero bytes, so it's
            // valid COBS, just too long), followed by the delimiter, then a
            // valid frame.
            let oversized: Vec<u8> = (0..MAX_FRAME_LEN + 10)
                .map(|i| (i % 255 + 1) as u8)
                .collect();
            let mut data = cobs::encode(&oversized);
            data.push(0x00);

            let mut good = cobs::encode(b"after overflow");
            good.push(0x00);
            data.append(&mut good);

            let mut io = SliceIo::new(data);

            assert!(matches!(read_frame(&mut io).await, Err(Error::Framing)));

            let frame = read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"after overflow");
        });
    }
}
