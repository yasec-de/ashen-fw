/* Reserves the last erase page (2K) of internal flash for FlashKeyStore
 * (see src/flash_keystore.rs).
 *
 * The section is NOLOAD: it occupies no space in the firmware image, so a
 * normal `probe-rs run`/`download` never writes to (and thus never erases)
 * this page, meaning the stored key survives reflashing. It still gets a
 * proper section header in the ELF, so its address and size are visible in
 * `nm`/`objdump`/the debugger.
 *
 * `_keystore_start` is exported for use from Rust (see
 * src/flash_keystore.rs) to compute the flash offset passed to
 * `FlashKeyStore::new`.
 *
 * This section is inserted after `.uninit` (a RAM section near the end of
 * the linker script), rather than after `.gnu.sgstubs` (in FLASH), so that
 * its location-counter advancement doesn't push `__veneer_limit` past
 * `_keystore_start` once the section has actual content.
 */
SECTIONS
{
  .keystore ORIGIN(FLASH) + LENGTH(FLASH) - 2K (NOLOAD) : ALIGN(4)
  {
    _keystore_start = .;
    KEEP(*(.keystore));
  } > FLASH
} INSERT AFTER .uninit

ASSERT(__veneer_limit <= _keystore_start, "
ERROR: the firmware image (.text/.rodata/.data) has grown into the reserved
.keystore page at the end of flash.");
