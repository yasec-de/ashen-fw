# Ashen Firmware

Firmware for a custom STM32G474RB-based board, written in Rust using
[Embassy](https://embassy.dev/).

On boot it blinks the status LED on PA5 and brings up an authenticated,
COBS-framed [Noise](https://noiseprotocol.org/) link over UART (see
[Secure Link](#secure-link)). The core COBS codec is formally verified with
[Verus](https://github.com/verus-lang/verus) (see
[Formal Verification](#formal-verification)).

## Building and Flashing

### Prerequisites

Software: Install Nix and enable flages
Hardware: STM32G474RB devboard, USB UART adapter, and ST-Link/V2 or compatible SWD debugger

### Build

```bash
nix build            # cross-compiled firmware ELF -> result/bin/ashen-fw
```

The flake pins the Rust toolchain (`rust-toolchain.toml`) and all build tools,
so Cargo is run through the dev shell rather than a system-wide install:

```bash
nix develop -c cargo build --release --features embedded --target thumbv7em-none-eabihf
```

### Flash

Flashing uses Cargo's runner configuration, which invokes
`probe-rs run --chip STM32G474RB` after building (configured in
`.cargo/config.toml`):

```bash
nix develop -c cargo run --release --features embedded --target thumbv7em-none-eabihf
```

### Development

```bash
nix develop  # Enter the development shell with all tools, then:

cargo build --release --features embedded --target thumbv7em-none-eabihf
cargo run   --release --features embedded --target thumbv7em-none-eabihf
cargo test                                 # host-side tests (see Secure Link)
cargo doc --open --no-deps
nix fmt                                    # Format all code (Rust, Nix, etc.)
```

The shell also provides the [Verus](https://github.com/verus-lang/verus)
verifier and Cargo helpers (`cargo-expand`, `cargo-bloat`, `cargo-binutils`).

For automatic environment activation, use direnv:
```bash
echo "use flake" > .envrc
direnv allow
```

## Secure Link

[`src/noise_link.rs`](src/noise_link.rs) implements a Noise_XX handshake
(trust-on-first-use of the remote static key) over a byte transport, with
an authenticated echo loop once the handshake completes. Messages are
framed by a variable-length, formally verified COBS codec
([`src/cobs.rs`](src/cobs.rs)) wrapped in a frame I/O layer
([`src/framing.rs`](src/framing.rs)). Frames are delimited by `0x00`; if a
frame is malformed, the implementation resynchronizes by discarding bytes
up to the next delimiter and continuing with the next frame.

The link is built as part of the `ashen_fw` library so it can be
exercised on the host:

```bash
nix develop -c cargo test
```

This builds the link implementation for the host, sets up an in-memory
duplex transport, runs the handshake, performs echo round trips
(including a multi-frame ~513-byte payload), and exercises frame
resynchronization. The `embedded` feature (off by
default) gates the firmware binary and its embedded-only dependencies,
which require the `thumbv7em-none-eabihf` target.

## Formal Verification

The core COBS codec in [`src/cobs.rs`](src/cobs.rs) is formally verified with
[Verus](https://github.com/verus-lang/verus). The *same* file is compiled into
the firmware and checked by the verifier — a normal `cargo build` erases the
proof annotations, so there is no separate, drifting copy. The frame I/O layer
that depends on the async/transport crates lives apart in
[`src/framing.rs`](src/framing.rs) to keep the verified file dependency-light.

Verified properties:

- `encode` never emits a `0x00` byte, so `0x00` is an unambiguous frame
  delimiter;
- `decode` never panics, never overflows, and never indexes out of bounds on
  zero-free input (the bytes it sees off the wire);
- round trip — `decode(encode(s)) == Ok(s)` for every input `s`.

Run the proof:

```bash
nix build .#cobs-proof          # runs Verus in the sandbox; fails on regression
# or, inside the dev shell:
nix develop -c verus --crate-type=lib src/cobs.rs
```

Verus ships an x86_64-linux prebuilt only, so the `verus` and `cobs-proof`
flake outputs are available on x86_64-linux.

## Debug Mode

The `debug-mode` Cargo feature is reserved for enabling more verbose
logging and debug-friendly clock configurations as the firmware grows:

```bash
nix develop -c cargo run --release --features debug-mode
```

## Project Structure

```
ashen-fw/
├── .github/workflows/ci.yml      # CI configuration
├── src/
│   ├── main.rs                   # Firmware entry point (`embedded` feature)
│   ├── lib.rs                    # Host-testable library root
│   ├── cobs.rs                   # Formally verified COBS codec (Verus)
│   ├── framing.rs                # COBS frame I/O over a byte transport
│   ├── noise_link.rs             # Noise_XX secure link
│   ├── protocol.rs               # Application request/response protocol
│   ├── flash_keystore.rs         # Persisted remote static key (embedded-only)
│   ├── hw_rng.rs                 # RNG peripheral driver (embedded-only)
│   ├── log.rs                    # plain-text logging over a byte pipe
│   ├── panic_link.rs             # Panic reporting over the link (embedded-only)
│   └── test_util.rs              # Host-side test helpers
├── nix/
│   ├── packages/ashen-fw.nix     # Firmware build derivation
│   ├── packages/cobs-proof.nix   # Verus COBS proof as a build step
│   ├── packages/verus.nix        # Pinned Verus toolchain
│   ├── devShells.nix             # Development environment
│   ├── overlays.nix              # Rust overlay composition
│   └── formatter.nix             # treefmt configuration
├── flake.nix                     # Flake entry point
├── rust-toolchain.toml           # Rust toolchain specification
└── .cargo/config.toml            # Build target and probe-rs runner
```

## License

MIT

## References

- [Embassy Documentation](https://embassy.dev/)
- [Verus](https://github.com/verus-lang/verus)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [Nix Flakes](https://nixos.wiki/wiki/Flakes)
- [rust-overlay](https://github.com/oxalica/rust-overlay)
- [probe-rs](https://probe.rs/)
- [STM32G4 Reference Manual](https://www.st.com/resource/en/reference_manual/rm0440-stm32g4-series-advanced-armbased-32bit-mcus-stmicroelectronics.pdf)
