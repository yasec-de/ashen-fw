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

/// On-flash layout of the persisted peer key. STM32G474 requires 8 byte alignment.
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


pub struct FlashKeyStore<'d> {
    flash: Flash<'d, Blocking>,
    cached: Option<[u8; 32]>,
}

impl<'d> FlashKeyStore<'d> {
    pub fn new(flash: Flash<'d, Blocking>) -> Self {
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
        self.erase();

        let mut magic_record = [0xFFu8; WRITE_SIZE];
        magic_record[0] = MAGIC;
        let magic_addr = unsafe { &raw const (*ptr).magic } as u32 - FLASH_BASE as u32;
        self.flash
            .blocking_write(magic_addr, &magic_record)
            .expect("flash write failed while persisting peer key");

        let key_addr = unsafe { &raw const (*ptr).key } as u32 - FLASH_BASE as u32;
        self.flash
            .blocking_write(key_addr, &key)
            .expect("flash write failed while persisting peer key");

        self.cached = Some(key);
    }

    fn erase(&mut self) {
        let ptr = KEYSTORE_RECORD.as_ptr();
        let page_start = ptr as u32 - FLASH_BASE as u32;

        self.flash
            .blocking_erase(page_start, page_start + MAX_ERASE_SIZE as u32)
            .expect("Peer key store flash erase failed");

        self.cached = None;
    }
}
