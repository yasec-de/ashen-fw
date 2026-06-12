//! Persists the trust-on-first-use (TOFU) remote static key to internal
//! flash, so it survives power cycles.

use core::mem::MaybeUninit;

use embassy_stm32::flash::{Blocking, FLASH_BASE, Flash, MAX_ERASE_SIZE, WRITE_SIZE};

use crate::noise_link::KeyStore;

/// Marks a stored record as containing a valid key. Erased flash reads back
/// as `0xFF`, so any other value (including the all-zero state of a freshly
/// erased-then-partially-written page) is treated as "no key stored".
const MAGIC: u8 = 0xA5;

const _: () = assert!(
    WRITE_SIZE == 8,
    "KeystoreRecord assumes 8-byte flash write granularity"
);

/// On-flash layout of the persisted TOFU record. `align(8)` matches
/// embassy-stm32's flash double-word write granularity (`WRITE_SIZE`), so
/// each field is independently writable.
///
/// To avoid leaving a stale [`MAGIC`] marker pointing at a partially-written
/// key if power is lost mid-write, the key is written *before* the magic
/// marker. If a write is interrupted before the magic field is written, the
/// page still reads back as "no key stored" rather than as a trusted key
/// with corrupted (and possibly attacker-influenced) bytes.
#[repr(C, align(8))]
struct KeystoreRecord {
    /// Validity marker (see [`MAGIC`]), padded to the flash write
    /// granularity so it can be written independently of `key`.
    magic: [u8; WRITE_SIZE],
    key: [u8; 32],
}

const _: () = assert!(
    core::mem::size_of::<KeystoreRecord>() <= MAX_ERASE_SIZE,
    "KeystoreRecord does not fit within a single erase page"
);

/// The reserved flash page for [`FlashKeyStore`] (see `keystore.x`), placed
/// in the `.keystore` linker section, which `keystore.x` positions at the
/// last erase page of flash. `MaybeUninit` + the section being `NOLOAD`
/// means this occupies no space in the firmware image.
///
/// Since flash is memory-mapped on STM32, this static doubles as a live,
/// directly-readable alias of the on-flash record.
#[unsafe(link_section = ".keystore")]
#[used]
static KEYSTORE_RECORD: MaybeUninit<KeystoreRecord> = MaybeUninit::uninit();

/// A [`KeyStore`] that persists the trusted remote static key to a region of
/// internal flash.
///
/// The trusted key (if any) is read once at construction time and cached,
/// since [`KeyStore::trusted_key`] takes `&self` but flash writes require
/// `&mut self`.
pub struct FlashKeyStore<'d> {
    flash: Flash<'d, Blocking>,
    cached: Option<[u8; 32]>,
}

impl<'d> FlashKeyStore<'d> {
    /// Opens the key store backed by `flash`, reading any previously stored
    /// key from the reserved `.keystore` flash page.
    pub fn new(flash: Flash<'d, Blocking>) -> Self {
        // SAFETY: KEYSTORE_RECORD is memory-mapped flash; reading it is
        // always valid (erased flash reads back as 0xFF).
        let record = unsafe { &*KEYSTORE_RECORD.as_ptr() };
        let cached = (record.magic[0] == MAGIC).then_some(record.key);

        Self { flash, cached }
    }
}

impl KeyStore for FlashKeyStore<'_> {
    fn trusted_key(&self) -> Option<[u8; 32]> {
        self.cached
    }

    fn trust(&mut self, key: [u8; 32]) {
        let ptr = KEYSTORE_RECORD.as_ptr();
        let page_start = ptr as u32 - FLASH_BASE as u32;
        let magic_addr = unsafe { &raw const (*ptr).magic } as u32 - FLASH_BASE as u32;
        let key_addr = unsafe { &raw const (*ptr).key } as u32 - FLASH_BASE as u32;

        let mut key_record = [0xFFu8; 32];
        key_record.copy_from_slice(&key);

        let mut magic_record = [0xFFu8; WRITE_SIZE];
        magic_record[0] = MAGIC;

        self.flash
            .blocking_erase(page_start, page_start + MAX_ERASE_SIZE as u32)
            .expect("flash erase failed while persisting TOFU key");
        // Write the key first; only write the magic marker once the key is
        // safely on flash, so a power loss in between leaves the page
        // reading back as "no key stored" rather than as a trusted key
        // backed by a corrupted/partial record.
        self.flash
            .blocking_write(key_addr, &key_record)
            .expect("flash write failed while persisting TOFU key");
        self.flash
            .blocking_write(magic_addr, &magic_record)
            .expect("flash write failed while persisting TOFU key");

        self.cached = Some(key);
    }

    fn erase(&mut self) {
        let ptr = KEYSTORE_RECORD.as_ptr();
        let page_start = ptr as u32 - FLASH_BASE as u32;

        self.flash
            .blocking_erase(page_start, page_start + MAX_ERASE_SIZE as u32)
            .expect("flash erase failed while erasing TOFU key");

        self.cached = None;
    }
}
