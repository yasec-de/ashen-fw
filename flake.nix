{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-25.05";
    nixpkgs-lib.url = "github:nix-community/nixpkgs.lib";
    rust-overlay.url = "github:oxalica/rust-overlay";
    rust-overlay.inputs.nixpkgs.follows = "nixpkgs";
    # A separate, newer rust-overlay used *only* to provide the exact stable
    # toolchain Verus was built against (see nix/packages/verus.nix). Kept
    # distinct from `rust-overlay` so bumping it never disturbs the firmware's
    # (undated) nightly toolchain.
    rust-overlay-verus.url = "github:oxalica/rust-overlay";
    rust-overlay-verus.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";
    treefmt-nix.url = "github:numtide/treefmt-nix";
  };

  outputs = flakeInputs: {
    devShells = import ./nix/devShells.nix flakeInputs;
    formatter = import ./nix/formatter.nix flakeInputs;
    formatterModule = import ./nix/formatter-module.nix flakeInputs;
    legacyPackages = import ./nix/legacy-packages.nix flakeInputs;
    overlays = import ./nix/overlays.nix flakeInputs;
    packages = import ./nix/packages flakeInputs;
  };
}
