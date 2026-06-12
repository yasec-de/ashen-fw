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
use std::fmt;

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


/// Errors that can occur while operating a [`NoiseLink`].
#[derive(Debug, Clone)]
pub enum Error {
    Transport(cobs::Error),
    Crypto(snow::Error),
    UntrustedPeer,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "Transport error: {}", e),
            Error::CryptO(e) => write!(f, "Noise protocol error: {}", e),
        }
    }
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Crypto(e)
    }
}

impl From<cobs::Error> for Error {
    fn from(e: cobs::Error) -> Self {
        Error::Transport(e)
    }
}

/// Storage for the remote long-term identity key.
pub trait KeyStore {
    fn trusted_key(&self) -> Option<[u8; 32]>;
    fn trust(&mut self, key: [u8; 32]);
    fn erase(&mut self);
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
/// [`NoiseLink::responder_handshake`].
pub fn generate_keypair(rng: Box<dyn Random>) -> Result<snow::Keypair, Error> {
    Ok(builder(rng)?.generate_keypair()?)
}

pub struct NoiseLink<T> {
    io: T,
    transport: TransportState,
    peer_trusted: bool,
    pub remote_static: [u8; 32],
}

impl<T: Read + Write> NoiseLink<T> {
    /// Performs the responder side of a Noise_XX handshake (`<- e, ee, s,
    /// es` then `-> s, se`), verifying the initiator's static key against
    /// `keystore` via TOFU.
    pub async fn responder_handshake<K: KeyStore>(
        mut io: T,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, Error> {
        let mut hs = builder(rng)?
            .local_private_key(local_static_key)?
            .build_responder()?;

        let mut buf = vec![0u8; cobs::MAX_PAYLOAD_LEN + 16];

        // -> e
        let msg = cobs::read_frame(io).await?;
        hs.read_message(&msg, &mut buf)?;

        // <- e, ee, s, es
        let len = hs.write_message(&[], &mut buf)?;
        cobs::write_frame(io, &buf[..len]).await?;

        // -> s, se
        let msg = cobs::read_frame(io).await?;
        hs.read_message(&msg, &mut buf)?;


        let remote_static = hs.get_remote_static().ok_or(Error::Crypto)?;
        let mut key = [0u8; 32];
        key.copy_from_slice(remote_static);

        let trusted = match keystore.trusted_key() {
            Some(trusted) => trusted.ct_eq(&key).into(),
            None => false,
        };

        let transport = hs.into_transport_mode()?;
        Ok(Self(io, transport, trusted, remote_static))
    }

    /// Encrypts and sends `payload` as a single transport message.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut cipher = vec![0u8; payload.len() + 16];
        let len = self.transport.write_message(payload, &mut cipher)?;
        match cobs::write_frame(&mut self.io, &cipher[..len]).await {
            Ok(v) => Ok(v),
            Err(cobs::Error::Overflow) => panic!("Overflow encoding outgoing payload"),
            Err(e) => Err(Error::Transport(e)),
        }
    }

    /// Receives and decrypts a single transport message.
    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let msg = cobs::read_frame(&mut self.io).await?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::XorShiftRng;

    /// Fixed seed used by all unit tests, so that test runs are
    /// deterministic and reproducible.
    const TEST_RNG_SEED: u64 = 0x1234_5678_9ABC_DEF0;

    /// Returns a fresh [`XorShiftRng`] seeded with [`TEST_RNG_SEED`].
    fn test_rng() -> Box<dyn Random> {
        Box::new(XorShiftRng::new(TEST_RNG_SEED))
    }

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

    impl<T: Read + Write> NoiseLink<T> {
        pub async fn initiator_handshake<K: KeyStore>(
            mut io: T,
            local_static_key: &[u8],
            rng: Box<dyn Random>,
            keystore: &mut K,
        ) -> Result<Self, Error> {
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

            let transport = hs.into_transport_mode()?;
            let link = Self {
                io,
                transport,
                true,
                remote_static,
            };
            log_tofu_status(newly_trusted);
            Ok(link)
        }
    }

    #[test]
    fn frame_round_trip() {
        embassy_futures::block_on(async {
            let mut io = SliceIo::new(Vec::new());
            cobs::write_frame(&mut io, b"hello world").await.unwrap();

            let mut reader = SliceIo::new(io.out);
            let frame = cobs::read_frame(&mut reader).await.unwrap();
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
            assert!(matches!(cobs::read_frame(&mut io).await, Err(Error::Framing)));

            // Reader has resynchronized and can decode the next frame.
            let frame = cobs::read_frame(&mut io).await.unwrap();
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

            assert!(matches!(cobs::read_frame(&mut io).await, Err(Error::Framing)));

            let frame = cobs::read_frame(&mut io).await.unwrap();
            assert_eq!(frame, b"after overflow");
        });
    }
}
