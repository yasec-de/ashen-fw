# Ashen Firmware

Firmware for a custom STM32G474RB-based board, written in Rust using
[Embassy](https://embassy.dev/).

This is a minimal starting point: it blinks the LED on PA5.

## Building and Flashing

### Prerequisites

Install Nix with flakes:
```bash
curl --proto '=https' --tlsv1.2 -sSf -L https://install.determinate.systems/nix | sh -s -- install
```

Hardware: ST-Link/V2 or compatible SWD debugger

### Build

```bash
nix build
# Binary at: result/bin/ashen-fw

# Or with cargo:
cargo build --release --features embedded --target thumbv7em-none-eabihf
```

### Flash

The project uses cargo's runner configuration for flashing:

```bash
cargo run --release --features embedded --target thumbv7em-none-eabihf
```

This automatically invokes `probe-rs run --chip STM32G474RB` after building (configured in `.cargo/config.toml`).

### Development

```bash
nix develop  # Enter development shell with all tools

# Available:
cargo build --release --features embedded --target thumbv7em-none-eabihf
cargo run --release --features embedded --target thumbv7em-none-eabihf
cargo doc --open --no-deps
nix fmt  # Format all code (Rust, Nix, etc.)
```

For automatic environment activation, use direnv:
```bash
echo "use flake" > .envrc
direnv allow
```

## Secure Link

[`src/noise_link.rs`](src/noise_link.rs) implements a Noise_XX handshake
(trust-on-first-use of the remote static key) framed with a vendored,
variable-length COBS implementation ([`src/cobs.rs`](src/cobs.rs)) over a
byte transport, with an authenticated echo loop once the handshake
completes. Frames are delimited by `0x00`; if a frame is malformed, the
implementation resynchronizes by discarding bytes up to the next
delimiter and continuing with the next frame. Errors encountered while
running the echo loop are recorded in a fixed-size ring buffer
([`src/error_log.rs`](src/error_log.rs), capacity 50) with their source,
a source-specific code, and the uptime (in seconds) at which they
occurred.

The link is built as part of the `ashen_fw` library so it can be
exercised on the host:

```bash
cargo test
```

This builds the link implementation for the host, sets up an in-memory
duplex transport, runs the handshake, performs echo round trips
(including a multi-frame ~513-byte payload), and exercises frame
resynchronization and error logging. The `embedded` feature (off by
default) gates the firmware binary and its embedded-only dependencies,
which require the `thumbv7em-none-eabihf` target.

## Debug Mode

The `debug-mode` Cargo feature is reserved for enabling more verbose
logging and debug-friendly clock configurations as the firmware grows:

```bash
cargo run --release --features debug-mode
```

## Project Structure

```
ashen-fw/
├── .github/workflows/ci.yml    # CI configuration
├── src/
│   └── main.rs                 # Application entry point
├── nix/
│   ├── packages/ashen-fw.nix   # Build derivation
│   ├── devShells.nix           # Development environment
│   ├── overlays.nix            # Rust overlay composition
│   └── formatter.nix           # treefmt configuration
├── flake.nix                   # Flake entry point
├── rust-toolchain.toml         # Rust toolchain specification
└── .cargo/config.toml          # Build target and probe-rs runner
```

## License

MIT

## References

- [Embassy Documentation](https://embassy.dev/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [rust-overlay](https://github.com/oxalica/rust-overlay)
- [probe-rs](https://probe.rs/)
- [STM32G4 Reference Manual](https://www.st.com/resource/en/reference_manual/rm0440-stm32g4-series-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)
