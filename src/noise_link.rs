//! Secure transport: Noise_XX over COBS-framed bytes (e.g. a USART link),
//! with trust-on-first-use (TOFU) verification of the remote static key.
//!
//! Wire framing: each message is encoded with [`crate::cobs`] and terminated
//! by a `0x00` delimiter byte, so frames may be of any length up to
//! [`cobs::MAX_PAYLOAD_LEN`]. If a frame is malformed (bad COBS encoding or
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

use crate::cobs;

/// Noise handshake pattern used for this link.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";


/// Errors that can occur while operating a [`NoiseLink`].
#[derive(Debug)]
pub enum Error {
    Transport(cobs::Error),
    Crypto(snow::Error),
    UntrustedPeer,
    /// A received payload could not be decoded as a protobuf [`Envelope`](crate::protocol::Envelope),
    /// or an [`Envelope`](crate::protocol::Envelope) could not be encoded.
    Protocol,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Error::Transport(e) => write!(f, "Transport error: {}", e),
            Error::Crypto(e) => write!(f, "Noise protocol error: {}", e),
            Error::UntrustedPeer => write!(f, "Untrusted peer"),
            Error::Protocol => write!(f, "Protobuf encode/decode error"),
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

pub(crate) fn builder(rng: Box<dyn Random>) -> Result<Builder<'static>, Error> {
    let params = NOISE_PATTERN.parse().map_err(Error::Crypto)?;
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
    pub(crate) io: T,
    pub(crate) transport: TransportState,
    pub(crate) peer_trusted: bool,
    pub remote_static: [u8; 32],
}

/// Performs the responder side of a Noise_XX handshake (`<- e, ee, s, es`
/// then `-> s, se`) over `io`, checking the initiator's static key against
/// `keystore`.
///
/// Returns the resulting [`TransportState`], the initiator's static key,
/// and whether it was already trusted (`true`) or hasn't been trusted yet
/// (`false`). A previously-trusted key that doesn't match is reported as
/// [`Error::UntrustedPeer`].
async fn do_responder_handshake<T: Read + Write, K: KeyStore>(
    io: &mut T,
    local_static_key: &[u8],
    rng: Box<dyn Random>,
    keystore: &mut K,
) -> Result<(TransportState, [u8; 32], bool), Error> {
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

    let remote_static = hs
        .get_remote_static()
        .expect("XX responder always learns remote static");
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
        let (transport, remote_static, peer_trusted) =
            do_responder_handshake(&mut io, local_static_key, rng, keystore).await?;

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

    /// Re-runs the responder handshake on this link's existing transport,
    /// replacing its transport state, [`NoiseLink::remote_static`], and
    /// trust status in place.
    pub async fn restart_responder<K: KeyStore>(
        &mut self,
        local_static_key: &[u8],
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<(), Error> {
        let (transport, remote_static, peer_trusted) =
            do_responder_handshake(&mut self.io, local_static_key, rng, keystore).await?;

        self.transport = transport;
        self.peer_trusted = peer_trusted;
        self.remote_static = remote_static;
        if !peer_trusted {
            // First connection: trust-on-first-use.
            self.trust(keystore);
        }
        Ok(())
    }

    /// Records this link's [`NoiseLink::remote_static`] as the trusted peer
    /// key in `keystore`, and marks this link as trusted.
    pub fn trust<K: KeyStore>(&mut self, keystore: &mut K) {
        keystore.trust(self.remote_static);
        self.peer_trusted = true;
    }

    /// Encrypts and sends `payload` as a single transport message.
    pub async fn send(&mut self, payload: &[u8]) -> Result<(), Error> {
        let mut cipher = vec![0u8; payload.len() + 16];
        let len = self.transport.write_message(payload, &mut cipher)?;
        cobs::write_frame(&mut self.io, &cipher[..len]).await?;
        Ok(())
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

