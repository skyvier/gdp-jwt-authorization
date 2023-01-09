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

module Validation.IssuedBy
  ( IssuedBy
  , ClaimsOf
  , getClaimsOf
  ) where

import Settings

import Data.Proxy

import GDP

import Control.Monad.Reader
import Control.Monad.Time
import Control.Monad.Trans.Except

import Control.Exception

import Crypto.JWT

import GHC.TypeLits

data IssuedBy token (source :: Symbol)

newtype ClaimsOf token = ClaimsOf Defn

newtype ValidationError = ValidationError JWTError
  deriving stock (Eq, Show)
  deriving anyclass (Exception)

signedBy
  :: forall source token m s.
      ( KnownSymbol source, Monad m, MonadTime m
      , MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> m (Either JWTError (ClaimsSet ~~ ClaimsOf token, Proof (token `IssuedBy` source)))
signedBy token = runExceptT $ do
  let getter = settings $ Proxy @source
  currentSettings <- asks getter
  let keys = validationKeySet currentSettings
      s = Settings.validationSettings currentSettings
  claims <- verifyClaims s keys $ the token
  return (defn claims, axiom)

getClaimsOf
  :: forall source token m s.
      ( KnownSymbol source, Monad m, MonadTime m
      , MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> m (Maybe (ClaimsSet ~~ ClaimsOf token ::: (token `IssuedBy` source)))
getClaimsOf token = do
  eClaims <- signedBy @source token
  case eClaims of
    Left _ -> return Nothing
    Right (namedClaims, proofOfSignature) ->
      return $ Just (namedClaims ...proofOfSignature)
