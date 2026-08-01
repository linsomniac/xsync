{
  description = "Stateless bidirectional directory synchronization over SSH";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-26.05";

  outputs =
    { self, nixpkgs }:
    let
      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
      nixpkgsFor = system: import nixpkgs { inherit system; };
      cargoPackage = (builtins.fromTOML (builtins.readFile ./Cargo.toml)).package;
      mkXsync =
        pkgs:
        pkgs.rustPlatform.buildRustPackage {
          pname = "xsync";
          inherit (cargoPackage) version;

          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.lock
              ./Cargo.toml
              ./src
              ./tests
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          meta = {
            description = "Stateless bidirectional directory synchronization over SSH";
            homepage = "https://github.com/linsomniac/xsync";
            license = pkgs.lib.licenses.mit;
            mainProgram = "xsync";
            platforms = pkgs.lib.platforms.unix;
          };
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor system;
          xsync = mkXsync pkgs;
        in
        {
          inherit xsync;
          default = xsync;
        }
      );

      apps = forAllSystems (system: {
        xsync = {
          type = "app";
          program = "${self.packages.${system}.xsync}/bin/xsync";
          meta.description = "Run xsync";
        };
        default = self.apps.${system}.xsync;
      });

      checks = forAllSystems (system: {
        inherit (self.packages.${system}) xsync;
      });

      overlays.default = final: _previous: {
        xsync = mkXsync final;
      };

      devShells = forAllSystems (
        system:
        let
          pkgs = nixpkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              cargo
              clippy
              rust-analyzer
              rustc
              rustfmt
            ];
            RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
          };
        }
      );

      formatter = forAllSystems (system: (nixpkgsFor system).nixfmt);
    };
}
