{
  description = "Modern forensic storage mounter & target unblocker TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Shared safety core, a sibling Cargo path dependency
    dfcore = {
      url = "github:tylerstyle/dfcore";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, dfcore }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfmount = pkgs.callPackage ./package.nix { dfcoreSrc = dfcore; };
      in
      {
        packages = {
          default = dfmount;
          dfmount = dfmount;
        };

        apps = {
          default = flake-utils.lib.mkApp {
            drv = dfmount;
          };
          dfmount = flake-utils.lib.mkApp {
            drv = dfmount;
          };
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ dfmount ];
          buildInputs = with pkgs; [
            rustc
            cargo
            rustfmt
            clippy
          ];
        };
      }
    );
}
