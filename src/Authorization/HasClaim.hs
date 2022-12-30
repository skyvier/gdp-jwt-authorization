{-# OPTIONS_GHC -Wno-warnings-deprecations  #-}

{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DeriveAnyClass #-}

module Authorization.HasClaim
  ( HasExtraClaimValue
  , hasExtraClaimWithValue
  ) where

import qualified Data.Aeson.Types as A
import qualified Data.Text as T
import Data.Proxy
import qualified Data.Map as M

import Control.Lens hiding ((...))

import GDP

import Crypto.JWT

import GHC.TypeLits

data HasExtraClaimValue claims (claimName :: Symbol) (claimValue :: Symbol)

hasExtraClaimWithValue
  :: forall claimName claimValue claims. (KnownSymbol claimName, KnownSymbol claimValue)
  => (ClaimsSet ~~ claims)
  -> Maybe (Proof (HasExtraClaimValue claims claimName claimValue))
hasExtraClaimWithValue c =
  let extraClaimName = T.pack $ symbolVal $ Proxy @claimName
      expectedValue = A.String $ T.pack $ symbolVal $ Proxy @claimValue
      extraClaims = view unregisteredClaims $ the c
      mClaim = M.lookup extraClaimName extraClaims
  in case mClaim of
      Just realValue ->
        if realValue == expectedValue
          then Just axiom
          else Nothing
      Nothing -> Nothing
