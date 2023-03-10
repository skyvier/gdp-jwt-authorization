{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
module App where

import App.Delete

import Settings

import Data.Aeson (encode)
import qualified Data.ByteString.Lazy as BS
import qualified Data.ByteString.Base64 as B64
import qualified Data.Text.IO as T
import qualified Data.Text.Encoding as T
import Data.Proxy

import Control.Monad.Reader
import Control.Monad.Trans.Except
import Control.Exception

import qualified Network.HTTP.Client as HTTP
import qualified Network.HTTP.Client.TLS as TLS
import Servant.API
import Servant.Client

import Crypto.JWT

interactiveTest :: IO ()
interactiveTest = do
  putStrLn "Insert a JWT"
  jwtText <- T.getLine
  -- this should be safe as long as the JWT is base64 encoded
  let jwtBs = BS.fromStrict $ T.encodeUtf8 jwtText
  signedJwt <- decodeJWT jwtBs
  testSettings <- getTestSettings
  runReaderT (deleteApplication signedJwt) testSettings

getTestSettings :: IO Settings
getTestSettings = do
  azureSettings <- getAzureSettings
  oktaSettings <- getAwsSettings
  return $ Settings
    { azureJwtSettings = azureSettings
    , oktaJwtSettings = oktaSettings
    }

getAwsSettings :: IO JWTSettings
getAwsSettings = do
  let audiencePred = const True
      encodedOctetsBS = T.encodeUtf8 hardcodedOctectsBase64
  hardcodedJwk <- case B64.decode encodedOctetsBS of
    Left _ -> fail "invalid key"
    Right decodedOctets -> pure (fromOctets decodedOctets)
  let jwkSet = JWKSet [hardcodedJwk]
  print $ encode jwkSet
  return $ JWTSettings (defaultJWTValidationSettings audiencePred) jwkSet

  where
    hardcodedOctectsBase64 =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

getAzureSettings :: IO JWTSettings
getAzureSettings =
  let audiencePred = const True
  in JWTSettings (defaultJWTValidationSettings audiencePred) <$> fetchJWKSet

type JWKSetApi = Get '[JSON] JWKSet

fetchJWKSet :: IO JWKSet
fetchJWKSet = do
  let publicKeysUrl =
        BaseUrl Https "login.microsoftonline.com" 443 "common/discovery/keys"
  HTTP.newManager TLS.tlsManagerSettings >>= \httpManager ->
    either throwIO pure =<<
      runClientM
        (client (Proxy :: Proxy JWKSetApi))
        (mkClientEnv httpManager publicKeysUrl)

decodeJWT :: BS.ByteString -> IO SignedJWT
decodeJWT jwtBs = do
  eJWT <- decode jwtBs
  case eJWT of
    Left _ -> error "invalid JWT"
    Right jwt -> return jwt

  where
    decode :: BS.ByteString -> IO (Either JWTError SignedJWT)
    decode bs = runExceptT $ decodeCompact bs
