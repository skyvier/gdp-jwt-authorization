{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE RankNTypes #-}
{-# LANGUAGE DeriveAnyClass #-}

module Validation.SignedWith (SignedBy, withClaimsSignedBy) where

import Settings

import Data.Proxy

import GDP

import Control.Monad.Reader
import Control.Monad.Time
import Control.Monad.Trans.Except

import Control.Exception

import Crypto.JWT

import GHC.TypeLits

data SignedBy (source :: Symbol) claims

newtype ValidationError = ValidationError JWTError
  deriving stock (Eq, Show)
  deriving anyclass (Exception)


signedBy
  :: forall source token m s. (KnownSymbol source, Monad m, MonadTime m, MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> m (Either JWTError ClaimsSet)
signedBy token = runExceptT $ do
  let getter = settings $ Proxy @source
  currentSettings <- asks getter
  let keys = validationKeySet currentSettings
      s = Settings.validationSettings currentSettings
  verifyClaims s keys $ the token

withClaimsSignedBy
  :: forall source token m s r. (KnownSymbol source, MonadIO m, MonadTime m, MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> (forall claims. (ClaimsSet ~~ claims ::: SignedBy source claims) -> m r)
  -> m r
withClaimsSignedBy token callback = do
  eClaims <- signedBy @source token
  case eClaims of
    Left err -> liftIO $ throwIO $ ValidationError err
    Right claims ->
      name claims $ \namedClaims ->
        callback (namedClaims ...axiom)
