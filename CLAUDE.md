# Ashen Firmware

STM32G474RB firmware (Embassy/embedded-rust) plus a host-testable
`ashen_fw` library (Noise_XX secure link, COBS framing, error log,
flash-backed key store, protobuf-based device protocol).

## Build/test setup

NEVER run `cargo` directly — it is not on `PATH` and will fail or use the
wrong toolchain. ALWAYS prefix every cargo invocation with `nix develop -c`.
This is enforced by a deny rule in `.claude/settings.json`, but apply it to
*every* cargo subcommand (`check`, `clippy`, `fmt`, etc.), not just
`test`/`build`/`run`.

Required commands:
```bash
nix develop -c cargo test                                                            # host tests
nix develop -c cargo build --release --features embedded --target thumbv7em-none-eabihf  # embedded build
nix develop -c cargo run   --release --features embedded --target thumbv7em-none-eabihf  # flash
nix build .#ashen-fw                                                                  # full from-scratch build + host tests (checkPhase)
```

Why Nix is required: the build needs `protoc` (for `build.rs`/`micropb-gen`)
and the `thumbv7em-none-eabihf` toolchain, which only `nix develop` provides.

Other notes:
- Host tests (`cargo test`) build with the `embedded` feature **off**, so
  `embassy-*`/`cortex-m`/etc. (gated under
  `[target.'cfg(target_os = "none")'.dependencies]`) are skipped.
- `nix build`'s `src` is git-tracked-files-only — `git add` any new
  source/test files (even if uncommitted) or the build fails with
  "couldn't read src/lib.rs"-style errors.

## Hardware notes

- `embassy-stm32` requires a `single-bank`/`dual-bank` feature; STM32G474RB
  (128KB flash) uses `single-bank`.
- `keystore.x` reserves the last 2KB flash page (NOLOAD) for
  `FlashKeyStore`'s TOFU key persistence; `scripts/erase-keystore.sh` can
  wipe it.
