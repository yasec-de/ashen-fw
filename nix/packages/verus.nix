{
  lib,
  stdenv,
  fetchzip,
  autoPatchelfHook,
  makeWrapper,
  zlib,
  # The exact stable Rust toolchain Verus was built against. Verus ships a
  # prebuilt `rust_verify` (a rustc driver) that is dynamically linked against
  # a specific `librustc_driver-<hash>.so` / `libstd-<hash>.so`; only the
  # matching upstream dist provides those exact sonames. Passed in from the
  # overlay so we can pin it independently of the firmware toolchain.
  verusRustToolchain,
}:
let
  # Must match version.json "toolchain" inside the release below.
  rustVersion = "1.96.0";
  version = "0.2026.06.14.4ea7d0f";
in
stdenv.mkDerivation {
  pname = "verus";
  inherit version;

  src = fetchzip {
    url = "https://github.com/verus-lang/verus/releases/download/release/${version}/verus-${version}-x86-linux.zip";
    # Strips the leading `verus-x86-linux/` directory.
    hash = "sha256-uJ85+QpsDExIoR83U9mqvN+VJ2S5hZ7q3+/d6VpJyEc=";
  };

  nativeBuildInputs = [
    autoPatchelfHook
    makeWrapper
  ];

  # autoPatchelfHook scans these for the libraries the prebuilt binaries
  # (rust_verify, z3, cargo-verus, the proc-macro .so's) need:
  #   - verusRustToolchain: librustc_driver-*.so, libstd-*.so
  #   - stdenv.cc.cc.lib:   libgcc_s, libstdc++ (z3)
  #   - zlib:               libz (z3)
  # Crucially, pointing rust_verify's RUNPATH at the toolchain's lib dir also
  # lets rustc derive its sysroot from the loaded librustc_driver.so, so no
  # rustup-managed sysroot is required.
  buildInputs = [
    stdenv.cc.cc.lib
    zlib
    verusRustToolchain
  ];

  dontBuild = true;

  installPhase = ''
    runHook preInstall

    mkdir -p $out/libexec/verus
    cp -r . $out/libexec/verus/

    # The `verus` launcher insists on a rustup installation purely to locate
    # the toolchain and run rust_verify under it. Linking and sysroot are
    # already handled by the patched RUNPATH above, so a tiny stub satisfies
    # the launcher's checks and execs the target directly.
    mkdir -p $out/libexec/rustup-stub
    cat > $out/libexec/rustup-stub/rustup <<EOF
    #!/bin/sh
    case "\$1" in
      toolchain) echo "${rustVersion}-x86_64-unknown-linux-gnu (default)";;
      run) shift 2; [ "\$1" = "--" ] && shift; exec "\$@";;
      show) echo "${rustVersion}-x86_64-unknown-linux-gnu";;
      *) exit 0;;
    esac
    EOF
    chmod +x $out/libexec/rustup-stub/rustup

    makeWrapper $out/libexec/verus/verus $out/bin/verus \
      --prefix PATH : $out/libexec/rustup-stub
    makeWrapper $out/libexec/verus/cargo-verus $out/bin/cargo-verus \
      --prefix PATH : $out/libexec/rustup-stub

    runHook postInstall
  '';

  meta = with lib; {
    description = "Verus: a tool for verifying the correctness of Rust code";
    homepage = "https://github.com/verus-lang/verus";
    license = with licenses; [ mit asl20 ];
    platforms = [ "x86_64-linux" ];
    mainProgram = "verus";
  };
}
