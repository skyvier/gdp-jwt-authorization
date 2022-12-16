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

module Authorization.HasRole (Role(..), RoleError, HasRole, hasRole, withRole) where

import Validation.SignedWith

import Data.Aeson
import Data.Proxy
import qualified Data.Map as M

import Control.Lens hiding ((...))
import Control.Monad (guard)
import Control.Monad.Trans.Maybe
import Control.Monad.Error.Class hiding (Error)

import GDP

import Crypto.JWT

import GHC.TypeLits
import GHC.Generics

newtype Role = Role { unRole :: String }
  deriving stock (Eq, Show, Generic)
  deriving newtype (ToJSON, FromJSON)

data HasRole (jwtRole :: Symbol) claims

data RoleError = DoesNotHaveRole
  deriving (Show, Eq)

withRole
  :: forall roleName claims r m. (KnownSymbol roleName, Monad m, MonadError RoleError m)
  => (ClaimsSet ~~ claims ::: SignedBy "azure" claims)
  -> ((ClaimsSet ~~ claims ::: HasRole roleName claims) -> m r)
  -> m r
withRole x callback = do
  mProof <- hasRole @roleName x
  case mProof of
    Nothing -> throwError DoesNotHaveRole
    Just proof -> callback (exorcise x...proof)

hasRole
  :: forall roleName claims m. (KnownSymbol roleName, Monad m)
  => (ClaimsSet ~~ claims ::: SignedBy "azure" claims)
  -> m (Maybe (Proof (HasRole roleName claims)))
hasRole c = runMaybeT $ do
  let necessaryRole = Role $ symbolVal $ Proxy @roleName
  roles <- MaybeT $ getRoles $ the c
  guard $ necessaryRole `elem` roles
  return axiom

getRoles :: Monad m => ClaimsSet -> m (Maybe [Role])
getRoles claims =
  let extraClaims = view unregisteredClaims claims
  in case M.lookup "roles" extraClaims of
    Nothing -> return Nothing
    Just roles ->
      let result :: Result [Role] = fromJSON roles
      in case result of
        Error _ -> return Nothing
        Success parsedResults -> return $ Just parsedResults
