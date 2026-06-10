#!/usr/bin/env bash
# Resets the FlashKeyStore page (the last 2K of flash, see keystore.x and
# src/flash_keystore.rs) back to its erased state (0xFF), which
# FlashKeyStore reads as "no key stored". Use this to forget the trusted
# remote static key, e.g. to re-pair the device.
set -euo pipefail

KEYSTORE_BASE_ADDRESS=0x0801F800
KEYSTORE_SIZE=2048

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
