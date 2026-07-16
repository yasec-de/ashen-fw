{
  lib,
  makeRustPlatform,
  rust-bin,
  rust-analyzer,
  probe-rs-tools,
  protobuf,
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
    protobuf
  ];

  # Disable auditable for embedded targets (doesn't work with rust-lld)
  auditable = false;

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

  doCheck = true;

  # Set RUST_SRC_PATH for rust-analyzer
  RUST_SRC_PATH = "${rustToolchain}/lib/rustlib/src/rust/library";

  meta = with lib; {
    description = "Ashen firmware.";
    license = licenses.mit;
    platforms = platforms.all;
  };
}
