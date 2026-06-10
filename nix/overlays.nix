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
    ;

  topLevelOverlay = topFinal: topPrev: {
    ashen-fw = topPrev.callPackage ./packages/ashen-fw.nix { };
  };

  rustOverlay = rust-overlay.overlays.default;
in
{
  default = composeManyExtensions ([
    topLevelOverlay
    rustOverlay
  ]);
}
