//! Secure transport: Noise_XX over COBS-framed bytes (e.g. a USART link),
//! with trust-on-first-use (TOFU) verification of the remote static key.
//!
//! Wire framing: each message is encoded with [`crate::framing`] and terminated
//! by a `0x00` delimiter byte, so frames may be of any length up to
//! [`framing::MAX_PAYLOAD_LEN`]. If a frame is malformed (bad COBS encoding or
//! larger than expected), the implementation resynchronizes by discarding
//! bytes up to the next `0x00` delimiter and continues with the following
//! frame.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::fmt;

use embedded_io_async::{Read, Write};
use subtle::ConstantTimeEq;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash};
pub use snow::types::Random;
use snow::{Builder, TransportState};

use crate::framing::{self, ResetReader};

/// Noise handshake pattern used for this link.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";


/// Errors that can occur while operating a [`NoiseLink`].
#[derive(Debug)]
pub enum Error {
    Transport(framing::Error),
    Crypto(snow::Error),
    Protocol,
    AlreadyKeyed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "Transport error: {}", e),
            Error::Crypto(e) => write!(f, "Noise protocol error: {}", e),
            Error::Protocol => write!(f, "Protobuf encode/decode error"),
            Error::AlreadyKeyed => write!(f, "Link already has a trusted peer"),
        }
    }
}

impl From<snow::Error> for Error {
    fn from(e: snow::Error) -> Self {
        Error::Crypto(e)
    }
}

impl From<framing::Error> for Error {
    fn from(e: framing::Error) -> Self {
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

pub(crate) fn builder(rng: Box<dyn Random>) -> Result<Builder<'static>, Error> {
    let params = NOISE_PATTERN.parse().map_err(Error::Crypto)?;
    Ok(Builder::with_resolver(
        params,
        Box::new(EmbeddedResolver::new(rng)),
    ))
}

pub fn generate_keypair(rng: Box<dyn Random>) -> Result<snow::Keypair, Error> {
    Ok(builder(rng)?.generate_keypair()?)
}

pub struct NoiseLink<T> {
    pub(crate) io: ResetReader<T>,
    pub(crate) transport: TransportState,
    pub(crate) peer_trusted: bool,
}

impl<T: Read + Write> NoiseLink<T> {
    pub async fn responder_handshake_retry<K: KeyStore, F>(
        mut io: ResetReader<T>,
        local_static_key: &[u8],
        mut fresh_rng: F,
        keystore: &mut K,
    ) -> Self
    where
        F: FnMut() -> Box<dyn Random>,
    {
        loop {
            match Self::responder_handshake(io, local_static_key, fresh_rng(), keystore).await {
                Ok(link) => return link,
                Err((_e, returned_io)) => {
                    io = returned_io;
                }
            }
        }
    }

    pub async fn responder_handshake<K: KeyStore>(
        mut io: ResetReader<T>,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, (Error, ResetReader<T>)> {
        let mut hs = match (|| {
            builder(rng)?
                .local_private_key(local_static_key)?
                .build_responder()
                .map_err(Error::from)
        })() {
            Ok(v) => v,
            Err(e) => return Err((e, io)),
        };

        let mut buf = vec![0u8; framing::MAX_PAYLOAD_LEN];

        let msg = match framing::read_frame(&mut io).await {
            Ok(v) => v,
            Err(e) => return Err((Error::from(e), io)),
        };
        if let Err(e) = hs.read_message(&msg, &mut buf) {
            return Err((Error::from(e), io));
        }

        // <- e, ee, s, es
        let len = match hs.write_message(&[], &mut buf) {
            Ok(v) => v,
            Err(e) => return Err((Error::from(e), io)),
        };
        if let Err(e) = framing::write_frame(&mut io, &buf[..len]).await {
            return Err((Error::from(e), io));
        }

        // -> s, se
        let msg = match framing::read_frame(&mut io).await {
            Ok(v) => v,
            Err(e) => return Err((Error::from(e), io)),
        };
        if let Err(e) = hs.read_message(&msg, &mut buf) {
            return Err((Error::from(e), io));
        }
        let transport = match hs.into_transport_mode() {
            Ok(v) => v,
            Err(e) => return Err((Error::from(e), io)),
        };

        let remote_static = transport
            .get_remote_static()
            .expect("XX responder always learns remote static");

        let peer_trusted = match keystore.trusted_key() {
            Some(trusted) => bool::from(trusted.ct_eq(&remote_static)),
            None => false,
        };

        let link = Self {
            io,
            transport,
            peer_trusted,
        };

        Ok(link)
    }

    fn remote_static_key(&self) -> [u8; 32] {
        let mut key = [0u8; 32];
        key.copy_from_slice(
            self.transport.get_remote_static().expect("XX responder always learns remote static"),
        );
        key
    }

    pub fn peer_key(&mut self) -> [u8; 32] {
        self.remote_static_key()
    }

    pub fn is_peer_trusted(&self) -> bool {
        self.peer_trusted
    }

    pub fn into_io(self) -> ResetReader<T> {
        self.io
    }

    pub fn trust<K: KeyStore>(&mut self, keystore: &mut K) -> Result<(), Error> {
        if keystore.trusted_key().is_some() {
            return Err(Error::AlreadyKeyed);
        }

        keystore.trust(self.remote_static_key());
        self.peer_trusted = true;
        Ok(())
    }

    pub async fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        const TAG_LEN: usize = 16;
        let mut ciphertext = vec![0u8; payload.len() + TAG_LEN];
        let len = self.transport.write_message(payload, &mut ciphertext)?;
        framing::write_frame(&mut self.io, &ciphertext[..len]).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let msg = framing::read_frame(&mut self.io).await?;
        let mut plaintext = vec![0u8; msg.len()];
        let len = self.transport.read_message(&msg, &mut plaintext)?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    pub async fn request(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.send(request).await?;
        self.receive().await
    }
}

