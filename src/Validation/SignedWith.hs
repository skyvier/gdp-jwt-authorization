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

module Validation.SignedWith (SignedBy, withClaimsSignedBy) where

import Settings

import Data.Proxy

import GDP

import Control.Monad.Reader
import Control.Monad.Error.Class hiding (Error)
import Control.Monad.Time


import Crypto.JWT

import GHC.TypeLits

data SignedBy (source :: Symbol) claims

signedBy
  :: forall source token m s. (KnownSymbol source, Monad m, MonadTime m, MonadError JWTError m, MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> m ClaimsSet
signedBy token = do
  let getter = settings $ Proxy @source
  currentSettings <- asks getter
  let keys = validationKeySet currentSettings
      s = Settings.validationSettings currentSettings
  verifyClaims s keys $ the token

withClaimsSignedBy
  :: forall source token m s r. (KnownSymbol source, Monad m, MonadTime m, MonadError JWTError m, MonadReader s m, HasSettings source s)
  => (SignedJWT ~~ token)
  -> (forall claims. (ClaimsSet ~~ claims ::: SignedBy source claims) -> m r)
  -> m r
withClaimsSignedBy token callback = do
  claims <- signedBy @source token
  name claims $ \namedClaims ->
    callback (namedClaims ...axiom)
