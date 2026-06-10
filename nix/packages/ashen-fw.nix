{
  lib,
  makeRustPlatform,
  rust-bin,
  rust-analyzer,
  probe-rs-tools,
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

  nativeBuildInputs = [
    rust-analyzer
    probe-rs-tools
  ];

  # Disable auditable for embedded targets (doesn't work with rust-lld)
  auditable = false;

  buildPhase = ''
    runHook preBuild
    cargo build --release --target thumbv7em-none-eabihf
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    mkdir -p $out/bin
    cp target/thumbv7em-none-eabihf/release/${cargoToml.package.name} $out/bin/
    runHook postInstall
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
