flakeInputs:
flakeInputs.nixpkgs-lib.lib.genAttrs
  [
    "x86_64-linux"
    "aarch64-linux"
  ]
  (
    system:
    let
      pkgs = flakeInputs.self.legacyPackages.${system};
      inherit (pkgs) ashen-fw;
    in
    {
      inherit ashen-fw;
      default = ashen-fw;
    }
    # Verus only ships a prebuilt x86_64-linux release.
    // flakeInputs.nixpkgs-lib.lib.optionalAttrs (system == "x86_64-linux") {
      inherit (pkgs) verus cobs-proof;
    }
  )
