{
  stdenvNoCC,
  verus,
}:
# Runs the Verus proof of the core COBS routines (see verif/cobs.rs) as a
# build step, so `nix build .#cobs-proof` fails if the proof ever breaks.
stdenvNoCC.mkDerivation {
  pname = "cobs-proof";
  version = "0.1.0";

  src = ../../verif;

  nativeBuildInputs = [ verus ];

  buildPhase = ''
    runHook preBuild
    verus cobs.rs
    runHook postBuild
  '';

  installPhase = ''
    runHook preInstall
    touch $out
    runHook postInstall
  '';

  meta.description = "Verus verification of ashen-fw's COBS encode/decode";
}
