//! Persists the trust-on-first-use (TOFU) remote static key to internal
//! flash, so it survives power cycles.

use alloc::vec;

use embedded_storage::nor_flash::NorFlash;

use crate::noise_link::KeyStore;

/// Marks a stored record as containing a valid key. Erased flash reads back
/// as `0xFF`, so any other value (including the all-zero state of a freshly
/// erased-then-partially-written page) is treated as "no key stored".
const MAGIC: u8 = 0xA5;

/// A [`KeyStore`] that persists the trusted remote static key to a region of
/// internal flash.
///
/// The region must be at least one erase page (`F::ERASE_SIZE` bytes) and is
/// fully erased and rewritten on every call to [`KeyStore::trust`]. The
/// trusted key (if any) is read once at construction time and cached, since
/// [`KeyStore::trusted_key`] takes `&self` but flash reads require `&mut
/// self`.
///
/// To avoid leaving a stale [`MAGIC`] marker pointing at a partially-written
/// key if power is lost mid-write, the key is written *before* the magic
/// marker (each in its own `F::WRITE_SIZE`-aligned chunk within the page). If
/// a write is interrupted before the magic chunk is written, the page still
/// reads back as "no key stored" rather than as a trusted key with corrupted
/// (and possibly attacker-influenced) bytes.
pub struct FlashKeyStore<F: NorFlash> {
    flash: F,
    offset: u32,
    cached: Option<[u8; 32]>,
}

unsafe extern "C" {
    /// Provided by `keystore.x`: the start of the `.keystore` section, i.e.
    /// the flash page reserved for [`FlashKeyStore`].
    static _keystore_start: u8;
}

/// The flash offset (from `embassy_stm32::flash::FLASH_BASE`) of the page
/// reserved for [`FlashKeyStore`] by `keystore.x`.
pub fn keystore_offset() -> u32 {
    let start = &raw const _keystore_start as u32;
    start - embassy_stm32::flash::FLASH_BASE as u32
}

impl<F: NorFlash> FlashKeyStore<F> {
    /// Opens the key store backed by `flash`, reading any previously stored
    /// key from the page at `offset`.
    ///
    /// `offset` must be aligned to `F::ERASE_SIZE`.
    pub fn new(mut flash: F, offset: u32) -> Self {
        assert!(
            (magic_chunk_len::<F>() + key_chunk_len::<F>()) as u32 <= F::ERASE_SIZE as u32,
            "FlashKeyStore record does not fit within a single erase page"
        );

        let mut magic = vec![0u8; magic_chunk_len::<F>()];
        let cached = match flash.read(offset, &mut magic) {
            Ok(()) if magic[0] == MAGIC => {
                let mut record = vec![0u8; key_chunk_len::<F>()];
                match flash.read(key_offset::<F>(offset), &mut record) {
                    Ok(()) => {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&record[..32]);
                        Some(key)
                    }
                    Err(_) => None,
                }
            }
            _ => None,
        };

        Self {
            flash,
            offset,
            cached,
        }
    }
}

/// The size of the magic/validity marker chunk: one byte, rounded up to a
/// whole number of `F::WRITE_SIZE` chunks.
fn magic_chunk_len<F: NorFlash>() -> usize {
    1usize.div_ceil(F::WRITE_SIZE) * F::WRITE_SIZE
}

/// The size of the key chunk: 32 bytes, rounded up to a whole number of
/// `F::WRITE_SIZE` chunks.
fn key_chunk_len<F: NorFlash>() -> usize {
    32usize.div_ceil(F::WRITE_SIZE) * F::WRITE_SIZE
}

/// The flash offset of the key chunk, immediately following the magic chunk.
fn key_offset<F: NorFlash>(offset: u32) -> u32 {
    offset + magic_chunk_len::<F>() as u32
}

impl<F: NorFlash> KeyStore for FlashKeyStore<F> {
    fn trusted_key(&self) -> Option<[u8; 32]> {
        self.cached
    }

    fn trust(&mut self, key: [u8; 32]) {
        let mut key_record = vec![0xFFu8; key_chunk_len::<F>()];
        key_record[..32].copy_from_slice(&key);

        let mut magic_record = vec![0xFFu8; magic_chunk_len::<F>()];
        magic_record[0] = MAGIC;

        self.flash
            .erase(self.offset, self.offset + F::ERASE_SIZE as u32)
            .expect("flash erase failed while persisting TOFU key");
        // Write the key first; only write the magic marker once the key is
        // safely on flash, so a power loss in between leaves the page
        // reading back as "no key stored" rather than as a trusted key
        // backed by a corrupted/partial record.
        self.flash
            .write(key_offset::<F>(self.offset), &key_record)
            .expect("flash write failed while persisting TOFU key");
        self.flash
            .write(self.offset, &magic_record)
            .expect("flash write failed while persisting TOFU key");

        self.cached = Some(key);
    }
}
