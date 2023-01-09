{-# OPTIONS_GHC -Wno-warnings-deprecations  #-}

{-# LANGUAGE DataKinds                  #-}
{-# LANGUAGE DeriveAnyClass             #-}
{-# LANGUAGE DeriveGeneric              #-}
{-# LANGUAGE DerivingStrategies         #-}
{-# LANGUAGE FlexibleContexts           #-}
{-# LANGUAGE GeneralisedNewtypeDeriving #-}
{-# LANGUAGE KindSignatures             #-}
{-# LANGUAGE OverloadedStrings          #-}
{-# LANGUAGE ScopedTypeVariables        #-}
{-# LANGUAGE TypeApplications           #-}
{-# LANGUAGE TypeOperators              #-}

module Validation.Okta.HasRole
  ( HasOktaRole
  , hasOktaRole
  ) where

import qualified Data.Aeson.Types    as A
import qualified Data.Map            as M
import           Data.Proxy
import qualified Data.Text           as T

import           Control.Lens        hiding ((...))
import           Crypto.JWT
import           GHC.TypeLits

import           GDP

import           Validation.IssuedBy

data HasOktaRole claims (roleName :: Symbol)

hasOktaRole
  :: forall roleName token. KnownSymbol roleName
  => (ClaimsSet ~~ ClaimsOf token ::: (token `IssuedBy` "okta"))
  -> Maybe (Proof (ClaimsOf token `HasOktaRole` roleName))
hasOktaRole c =
  let extraClaimName = T.pack $ symbolVal $ Proxy @roleName
      extraClaims = view unregisteredClaims $ the c
      mClaim = M.lookup extraClaimName extraClaims
  in case mClaim of
      Just (A.String "true") -> Just axiom
      _                      -> Nothing
