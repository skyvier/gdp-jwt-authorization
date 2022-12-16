{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc902" }:
nixpkgs.pkgs.haskell.packages.${compiler}.callPackage ./gdp-simple.nix { }
