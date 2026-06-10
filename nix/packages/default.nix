flakeInputs:
flakeInputs.nixpkgs-lib.lib.genAttrs
  [
    "x86_64-linux"
    "aarch64-linux"
  ]
  (
    system:
    let
      inherit (flakeInputs.self.legacyPackages.${system})
        ashen-fw
        ;
    in
    {
      inherit ashen-fw;
      default = ashen-fw;
    }
  )
