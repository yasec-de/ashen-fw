#!/usr/bin/env bash
# Resets the FlashKeyStore page (the last 2K of flash, see keystore.x and
# src/flash_keystore.rs) back to its erased state (0xFF), which
# FlashKeyStore reads as "no key stored". Use this to forget the trusted
# remote static key, e.g. to re-pair the device.
set -euo pipefail

# KEYSTORE_SIZE must match the page size reserved by the `.keystore` section
# in keystore.x (currently `2K`).
KEYSTORE_SIZE=2048

ELF="target/thumbv7em-none-eabihf/release/ashen-fw"
if [ ! -f "$ELF" ]; then
    echo "error: $ELF not found." >&2
    echo "Build it first: cargo build --release --features embedded --target thumbv7em-none-eabihf" >&2
    exit 1
fi

# Read the address of `_keystore_start` (exported by keystore.x, see
# src/flash_keystore.rs) directly from the built firmware, so this script
# can't desync from the linker script's reservation.
KEYSTORE_BASE_ADDRESS=$(nm "$ELF" | awk '/ _keystore_start$/ {print "0x"$1; exit}')
if [ -z "$KEYSTORE_BASE_ADDRESS" ]; then
    echo "error: could not find _keystore_start symbol in $ELF" >&2
    exit 1
fi

tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

head -c "$KEYSTORE_SIZE" /dev/zero | tr '\0' '\377' > "$tmpfile"

probe-rs download \
    --chip STM32G474RB \
    --connect-under-reset \
    --protocol swd \
    --binary-format bin \
    --base-address "$KEYSTORE_BASE_ADDRESS" \
    "$tmpfile"
