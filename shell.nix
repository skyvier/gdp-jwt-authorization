{ nixpkgs ? import <nixpkgs> {}, compiler ? "ghc902" }:
(import ./default.nix { inherit nixpkgs compiler; }).env
