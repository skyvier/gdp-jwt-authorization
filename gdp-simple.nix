{ mkDerivation, aeson, base, bytestring, containers, gdp
, http-client, http-client-tls, jose, lens, lib, monad-time, mtl
, servant, servant-client, text, transformers
}:
mkDerivation {
  pname = "gdp-simple";
  version = "0.1.0.0";
  src = ./.;
  libraryHaskellDepends = [
    aeson base bytestring containers gdp http-client http-client-tls
    jose lens monad-time mtl servant servant-client text transformers
  ];
  license = lib.licenses.asl20;
}
