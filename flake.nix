{
  description = "Modern forensic storage mounter & target unblocker TUI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        dfmount = pkgs.callPackage ./package.nix { };
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
