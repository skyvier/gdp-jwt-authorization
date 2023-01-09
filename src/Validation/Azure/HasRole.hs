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

module Validation.Azure.HasRole
  ( HasAzureRole
  , hasAzureRole
  ) where

import Data.Aeson
import Data.Proxy
import qualified Data.Map as M

import Control.Lens hiding ((...))
import Control.Exception

import GDP

import Crypto.JWT

import GHC.TypeLits
import GHC.Generics

import Validation.IssuedBy

newtype Role = Role { unRole :: String }
  deriving stock (Eq, Show, Generic)
  deriving newtype (ToJSON, FromJSON)

data HasAzureRole claims (jwtRole :: Symbol)

data RoleError = DoesNotHaveRole
  deriving stock (Show, Eq)
  deriving anyclass (Exception)

hasAzureRole
  :: forall roleName token. KnownSymbol roleName
  => (ClaimsSet ~~ ClaimsOf token ::: (token `IssuedBy` "azure"))
  -> Maybe (Proof (ClaimsOf token  `HasAzureRole` roleName))
hasAzureRole c =
  let necessaryRole = Role $ symbolVal $ Proxy @roleName
      mRoles = getRoles $ the c
      hasNecessaryRole = maybe False (elem necessaryRole) mRoles
  in if hasNecessaryRole then Just axiom else Nothing

getRoles :: ClaimsSet -> Maybe [Role]
getRoles claims =
  let extraClaims = view unregisteredClaims claims
  in case M.lookup "roles" extraClaims of
    Nothing -> Nothing
    Just roles ->
      let result :: Result [Role] = fromJSON roles
      in case result of
        Error _ -> Nothing
        Success parsedResults -> Just parsedResults
