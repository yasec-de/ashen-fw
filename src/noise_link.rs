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
use core::cell::{Cell, RefCell};
use core::fmt;

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use curve25519_dalek::montgomery::MontgomeryPoint;
use embedded_io_async::{Read, Write};
use subtle::ConstantTimeEq;
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash};
pub use snow::types::Random;
use snow::{Builder, TransportState};
use zeroize::{Zeroizing, zeroize_stack};

use crate::framing::{self, ResetReader};
use crate::masked_memory::MaskedCell;

/// Noise handshake pattern used for this link.
pub const NOISE_PATTERN: &str = "Noise_XX_25519_ChaChaPoly_SHA256";

/// Length of a Curve25519 scalar/point and of a ChaCha20-Poly1305 key.
const KEY_LEN: usize = 32;
/// Length of a Poly1305 authentication tag.
const TAG_LEN: usize = 16;
/// `Cipher`s snow resolves per handshake: one for the symmetric state, plus
/// the two that become the transport `CipherStates`.
const CIPHER_SLOTS: usize = 3;
/// `Dh`s snow resolves per handshake: the local static and the ephemeral one.
const DH_SLOTS: usize = 2;


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

/// The per-handshake private key material snow asks its resolver for. Kept in
/// one [`MaskedCell`] so that a re-handshake reuses the registration instead of
/// adding another one.
#[derive(Clone, Copy, Default)]
pub(crate) struct SessionKeys {
    cipher: [[u8; KEY_LEN]; CIPHER_SLOTS],
    dh: [[u8; KEY_LEN]; DH_SLOTS],
}

/// Every private key this link holds, in masked storage.
///
/// The identity key sits in its own cell so that a borrow of it can be held
/// across [`Builder::build_responder`], which writes the same key back into a
/// [`MaskedDh`] slot of the session cell.
#[derive(Clone, Copy)]
pub struct SecretKeys {
    pub(crate) identity: MaskedCell<[u8; KEY_LEN]>,
    pub(crate) session: MaskedCell<SessionKeys>,
}

impl SecretKeys {
    pub fn generate(mut rng: Box<dyn Random>) -> Result<(SecretKeys, [u8; KEY_LEN]), Error> {
        let keys = SecretKeys {
            identity: MaskedCell::new(),
            session: MaskedCell::new(),
        };

        let public = {
            let mut identity = keys.identity.borrow_mut();
            rng.try_fill_bytes(&mut identity[..])?;
            MontgomeryPoint::mul_base_clamped(*identity).to_bytes()
        };

        Ok((keys, public))
    }

    pub fn from_identity(identity: &[u8]) -> SecretKeys {
        let keys = SecretKeys {
            identity: MaskedCell::new(),
            session: MaskedCell::new(),
        };

        keys.identity
            .borrow_mut()
            .copy_from_slice(&identity[..KEY_LEN]);

        keys
    }
}

pub fn generate_keypair(mut rng: Box<dyn Random>) -> Result<snow::Keypair, Error> {
    let mut private = Zeroizing::new([0u8; KEY_LEN]);
    rng.try_fill_bytes(&mut private[..])?;
    let public = MontgomeryPoint::mul_base_clamped(*private).to_bytes();

    Ok(snow::Keypair {
        private: private.to_vec(),
        public: public.to_vec(),
    })
}

/// A [`Cipher`] equivalent to the `ChaChaPoly` one from [`DefaultResolver`],
/// except that its key lives in a [`SessionKeys`] slot rather than inside this
/// struct. The cipher instance is built per operation from a short borrow, so
/// the key only ever appears in transient stack memory.
struct MaskedCipher {
    keys: MaskedCell<SessionKeys>,
    slot: usize,
}

/// SAFETY: [`Cipher`] requires `Send + Sync`, but nothing in snow shares one
/// across threads, and the whole link runs on a single executor.
unsafe impl Send for MaskedCipher {}
unsafe impl Sync for MaskedCipher {}

impl Cipher for MaskedCipher {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8; KEY_LEN]) {
        self.keys.borrow_mut().cipher[self.slot] = *key;
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

        out[..plaintext.len()].copy_from_slice(plaintext);

        let tag = {
            let key = Zeroizing::new(self.keys.borrow().cipher[self.slot]);
            ChaCha20Poly1305::new(Key::from_slice(&key[..]))
                .encrypt_in_place_detached(
                    &nonce_bytes.into(),
                    authtext,
                    &mut out[..plaintext.len()],
                )
                .expect("ChaCha20-Poly1305 encryption failed")
        };

        out[plaintext.len()..][..tag.len()].copy_from_slice(&tag);
        plaintext.len() + tag.len()
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_le_bytes());

        let message_len = ciphertext.len() - TAG_LEN;
        out[..message_len].copy_from_slice(&ciphertext[..message_len]);

        let key = Zeroizing::new(self.keys.borrow().cipher[self.slot]);
        ChaCha20Poly1305::new(Key::from_slice(&key[..]))
            .decrypt_in_place_detached(
                &nonce_bytes.into(),
                authtext,
                &mut out[..message_len],
                ciphertext[message_len..].into(),
            )
            .map_err(|_| snow::Error::Decrypt)?;

        Ok(message_len)
    }
}

/// A [`Dh`] equivalent to the `25519` one from [`DefaultResolver`], except that
/// the private key lives in a [`SessionKeys`] slot. The public key is not
/// secret and is cached here in the clear.
struct MaskedDh {
    keys: MaskedCell<SessionKeys>,
    slot: usize,
    pubkey: [u8; KEY_LEN],
}

/// SAFETY: see [`MaskedCipher`].
unsafe impl Send for MaskedDh {}
unsafe impl Sync for MaskedDh {}

impl MaskedDh {
    fn derive_pubkey(&mut self) {
        let privkey = Zeroizing::new(self.keys.borrow().dh[self.slot]);
        self.pubkey = MontgomeryPoint::mul_base_clamped(*privkey).to_bytes();
    }
}

impl Dh for MaskedDh {
    fn name(&self) -> &'static str {
        "25519"
    }

    fn pub_len(&self) -> usize {
        KEY_LEN
    }

    fn priv_len(&self) -> usize {
        KEY_LEN
    }

    fn set(&mut self, privkey: &[u8]) {
        self.keys.borrow_mut().dh[self.slot].copy_from_slice(&privkey[..KEY_LEN]);
        self.derive_pubkey();
    }

    fn generate(&mut self, rng: &mut dyn Random) -> Result<(), snow::Error> {
        let mut privkey = Zeroizing::new([0u8; KEY_LEN]);
        rng.try_fill_bytes(&mut privkey[..])?;
        self.keys.borrow_mut().dh[self.slot] = *privkey;
        self.derive_pubkey();
        Ok(())
    }

    fn pubkey(&self) -> &[u8] {
        &self.pubkey
    }

    /// Unused: the only caller in snow is `Builder::generate_keypair`, which
    /// [`generate_keypair`] replaces precisely because a masked key cannot be
    /// handed out by reference.
    fn privkey(&self) -> &[u8] {
        unreachable!("masked private keys are never handed out by reference")
    }

    fn dh(&self, pubkey: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        let mut peer = [0u8; KEY_LEN];
        peer.copy_from_slice(&pubkey[..KEY_LEN]);

        let shared = {
            let privkey = Zeroizing::new(self.keys.borrow().dh[self.slot]);
            Zeroizing::new(MontgomeryPoint(peer).mul_clamped(*privkey).to_bytes())
        };

        out[..KEY_LEN].copy_from_slice(&shared[..]);
        Ok(())
    }
}

/// A [`snow::resolvers::CryptoResolver`] that delegates hashing to
/// [`DefaultResolver`], uses a caller-supplied [`Random`] implementation as the
/// RNG, and answers cipher/DH requests with [`MaskedCipher`]/[`MaskedDh`] bound
/// to successive slots of a [`SessionKeys`] cell.
///
/// The supplied RNG is consumed by the first call to
/// [`resolve_rng`](CryptoResolver::resolve_rng) (the only call snow makes per
/// handshake). The slot counters likewise assume one handshake per resolver.
struct EmbeddedResolver {
    rng: RefCell<Option<Box<dyn Random>>>,
    keys: MaskedCell<SessionKeys>,
    next_cipher: Cell<usize>,
    next_dh: Cell<usize>,
    inner: DefaultResolver,
}

/// SAFETY: see [`MaskedCipher`]. `Builder::with_resolver` requires `Send`.
unsafe impl Send for EmbeddedResolver {}

impl EmbeddedResolver {
    fn new(rng: Box<dyn Random>, keys: MaskedCell<SessionKeys>) -> Self {
        Self {
            rng: RefCell::new(Some(rng)),
            keys,
            next_cipher: Cell::new(0),
            next_dh: Cell::new(0),
            inner: DefaultResolver,
        }
    }

    fn take_slot(counter: &Cell<usize>, limit: usize) -> Option<usize> {
        let slot = counter.get();
        if slot >= limit {
            return None;
        }
        counter.set(slot + 1);
        Some(slot)
    }
}

impl CryptoResolver for EmbeddedResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.rng.borrow_mut().take()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        if !matches!(choice, DHChoice::Curve25519) {
            return self.inner.resolve_dh(choice);
        }

        Some(Box::new(MaskedDh {
            keys: self.keys,
            slot: Self::take_slot(&self.next_dh, DH_SLOTS)?,
            pubkey: [0u8; KEY_LEN],
        }))
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.inner.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        if !matches!(choice, CipherChoice::ChaChaPoly) {
            return self.inner.resolve_cipher(choice);
        }

        Some(Box::new(MaskedCipher {
            keys: self.keys,
            slot: Self::take_slot(&self.next_cipher, CIPHER_SLOTS)?,
        }))
    }
}

pub(crate) fn builder(rng: Box<dyn Random>, keys: SecretKeys) -> Result<Builder<'static>, Error> {
    let params = NOISE_PATTERN.parse().map_err(Error::Crypto)?;
    Ok(Builder::with_resolver(
        params,
        Box::new(EmbeddedResolver::new(rng, keys.session)),
    ))
}

pub struct NoiseLink<T> {
    pub(crate) io: ResetReader<T>,
    pub(crate) transport: TransportState,
    pub(crate) peer_trusted: bool,
}

impl<T: Read + Write> NoiseLink<T> {
    pub async fn responder_handshake_retry<K: KeyStore, F>(
        mut io: ResetReader<T>,
        keys: SecretKeys,
        mut fresh_rng: F,
        keystore: &mut K,
    ) -> Self
    where
        F: FnMut() -> Box<dyn Random>,
    {
        loop {
            let outcome = Self::responder_handshake(io, keys, fresh_rng(), keystore).await;
            zeroize_stack::<2048>();

            match outcome {
                Ok(link) => return link,
                Err((_e, returned_io)) => {
                    io = returned_io;
                }
            }
        }
    }

    pub async fn responder_handshake<K: KeyStore>(
        mut io: ResetReader<T>,
        keys: SecretKeys,
        rng: Box<dyn Random>,
        keystore: &mut K,
    ) -> Result<Self, (Error, ResetReader<T>)> {
        let mut hs = match (|| {
            let identity = keys.identity.borrow();
            builder(rng, keys)?
                .local_private_key(&identity[..])?
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
        let mut ciphertext = vec![0u8; payload.len() + TAG_LEN];
        let result = self.transport.write_message(payload, &mut ciphertext);
        zeroize_stack::<1024>();
        let len = result?;
        framing::write_frame(&mut self.io, &ciphertext[..len]).await?;
        Ok(())
    }

    pub async fn receive(&mut self) -> Result<Vec<u8>, Error> {
        let msg = framing::read_frame(&mut self.io).await?;
        let mut plaintext = vec![0u8; msg.len()];
        let result = self.transport.read_message(&msg, &mut plaintext);
        zeroize_stack::<1024>();
        let len = result?;
        plaintext.truncate(len);
        Ok(plaintext)
    }

    pub async fn request(&mut self, request: &[u8]) -> Result<Vec<u8>, Error> {
        self.send(request).await?;
        self.receive().await
    }
}
