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
    in
    {
      default = pkgs.mkShell {
        name = "ashen-fw-dev";

        # Inherit all build inputs from the ashen-fw package
        inputsFrom = [ pkgs.ashen-fw ];

        # Add additional development-only tools
        nativeBuildInputs = with pkgs; [
          cargo-expand
          cargo-bloat
          cargo-binutils
        ];

        shellHook = ''
          function git_branch {
            git rev-parse --abbrev-ref HEAD 2>/dev/null
          }
          export PS1="\[\e[0;32m\]\u@\h\[\e[0m\]:\[\e[0;34m\]\w\[\e[0m\] \$(git_branch)\[\e[0m\]\$ "
        '';
      };
    }
  )
