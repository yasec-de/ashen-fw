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
cargo build --release --target thumbv7em-none-eabihf
```

### Flash

The project uses cargo's runner configuration for flashing:

```bash
cargo run --release
```

This automatically invokes `probe-rs run --chip STM32G474RB` after building (configured in `.cargo/config.toml`).

### Development

```bash
nix develop  # Enter development shell with all tools

# Available:
cargo build --release
cargo run --release
cargo doc --open --no-deps
nix fmt  # Format all code (Rust, Nix, etc.)
```

For automatic environment activation, use direnv:
```bash
echo "use flake" > .envrc
direnv allow
```

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
