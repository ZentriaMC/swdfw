{
  description = "swdfw";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    fcos-harness.url = "github:ZentriaMC/fcos-harness";
    fcos-harness.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, flake-utils, fcos-harness, ... }:
    let
      supportedSystems = [
        "aarch64-darwin"
        "aarch64-linux"
        "x86_64-darwin"
        "x86_64-linux"
      ];
    in
    flake-utils.lib.eachSystem supportedSystems (system:
      let
        rev = self.rev or "dirty";
        pkgs = nixpkgs.legacyPackages.${system};
      in
      rec {
        devShell = pkgs.mkShell {
          buildInputs = [
            pkgs.butane
            pkgs.go
            pkgs.golangci-lint
            pkgs.gopls
            pkgs.qemu
            fcos-harness.packages.${system}.default
          ];

          BUTANE = "${pkgs.butane}/bin/butane";
        };
      });
}
