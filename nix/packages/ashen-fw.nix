{
  lib,
  makeRustPlatform,
  rust-bin,
  rust-analyzer,
  probe-rs-tools,
  gcc-arm-embedded,
  stdenv,
}:
let
  cargoToml = builtins.fromTOML (builtins.readFile ../../Cargo.toml);

  rustToolchain = rust-bin.fromRustupToolchainFile ../../rust-toolchain.toml;

  rustPlatform = makeRustPlatform {
    cargo = rustToolchain;
    rustc = rustToolchain;
  };
in
rustPlatform.buildRustPackage {
  pname = cargoToml.package.name;
  inherit (cargoToml.package) version;

  src = ../../.;

  cargoLock = {
    lockFile = ../../Cargo.lock;
  };

  # embassy-stm32 0.6.0 (and upstream main as of 2026-07) resets the GPDMA
  # channel in configure_linked_list() without first suspending it. On a
  # stop/restart of the ring-buffered UART RX (e.g. after a UART error) this
  # raises a GPDMA user-settings error, whose IRQ handler panics — observed as
  # a HardFault mid-session. The vendored crate copy is writable, so patch it.
  postPatch = ''
    patch -p1 -d "$cargoDepsCopy/embassy-stm32-0.6.0" \
      < ${../patches/embassy-stm32-gpdma-linked-list-reset.patch}
  '';

  nativeBuildInputs = [
    rust-analyzer
    probe-rs-tools
    gcc-arm-embedded
  ];

  # Disable auditable for embedded targets (doesn't work with rust-lld)
  auditable = false;

  CC_thumbv8m_main_none_eabihf = "arm-none-eabi-gcc";
  AR_thumbv8m_main_none_eabihf = "arm-none-eabi-ar";
  CC_x86_64_unknown_linux_gnu = "${stdenv.cc}/bin/cc";

  buildPhase = ''
    runHook preBuild
    cargo build --release --features embedded --target thumbv8m.main-none-eabihf
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    cp target/thumbv8m.main-none-eabihf/release/${cargoToml.package.name} $out/bin/
    runHook postInstall
  '';

  checkPhase = ''
    runHook preCheck
    cargo test --release
    runHook postCheck
  '';

  doCheck = false;

  # Set RUST_SRC_PATH for rust-analyzer
  RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

  meta = with lib; {
    description = "Ashen firmware.";
    license = licenses.mit;
    platforms = platforms.all;
  };
}
