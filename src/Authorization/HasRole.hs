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

module Authorization.HasRole (Role(..), RoleError, HasRole, hasRole, withRole) where

import Data.Aeson
import Data.Proxy
import qualified Data.Map as M

import Control.Lens hiding ((...))
import Control.Monad.IO.Class
import Control.Exception

import GDP

import Crypto.JWT

import GHC.TypeLits
import GHC.Generics

newtype Role = Role { unRole :: String }
  deriving stock (Eq, Show, Generic)
  deriving newtype (ToJSON, FromJSON)

data HasRole claims (jwtRole :: Symbol)

data RoleError = DoesNotHaveRole
  deriving stock (Show, Eq)
  deriving anyclass (Exception)

withRole
  :: forall roleName claims r m. (KnownSymbol roleName, Monad m, MonadIO m)
  => (ClaimsSet ~~ claims)
  -> (Proof (claims `HasRole` roleName) -> m r)
  -> m r
withRole x callback = do
  let mProof = hasRole @roleName x
  case mProof of
    Nothing -> liftIO $ throwIO DoesNotHaveRole
    Just proof -> callback proof

hasRole
  :: forall roleName claims. KnownSymbol roleName
  => (ClaimsSet ~~ claims)
  -> Maybe (Proof (claims `HasRole` roleName))
hasRole c =
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
