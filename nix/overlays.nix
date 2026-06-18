flakeInputs:
let
  inherit (flakeInputs.nixpkgs-lib)
    lib
    ;

  inherit (lib)
    composeManyExtensions
    ;

  inherit (flakeInputs)
    rust-overlay
    rust-overlay-verus
    ;

  topLevelOverlay = topFinal: topPrev: {
    ashen-fw = topPrev.callPackage ./packages/ashen-fw.nix { };

    verus = topPrev.callPackage ./packages/verus.nix {
      # Pull the exact stable toolchain Verus needs from a newer rust-overlay,
      # applied in isolation so it does not affect any other rust-* attribute.
      verusRustToolchain =
        (topPrev.appendOverlays [ rust-overlay-verus.overlays.default ]).rust-bin.stable."1.96.0".default;
    };

    cobs-proof = topFinal.callPackage ./packages/cobs-proof.nix { };
  };

  rustOverlay = rust-overlay.overlays.default;
in
{
  default = composeManyExtensions ([
    topLevelOverlay
    rustOverlay
  ]);
}
