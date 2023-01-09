{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE TypeOperators #-}

module App.Delete where

import Settings
import Authorization.Axioms

import Validation.IssuedBy
import Validation.Azure.HasRole

import Control.Monad.Reader
import Control.Monad.Trans.Maybe
import Control.Monad.Time

import GDP

import Crypto.JWT

deleteApplicationSafe
  :: MonadIO m
  => Proof (CanDeleteApps token)
  -> m ()
deleteApplicationSafe _ = liftIO $ putStrLn "Done"

deleteApplication
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, MonadIO m
     )
  => SignedJWT
  -> m ()
deleteApplication jwt =
  name jwt $ \namedJwt -> do
    mProof <- buildAuthorizationProof namedJwt
    case mProof of
      Just proof -> deleteApplicationSafe proof
      Nothing -> liftIO $ putStrLn "Unauthorized"

buildAuthorizationProof
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, MonadIO m
     )
  => SignedJWT ~~ token
  -> m (Maybe (Proof (CanDeleteApps token)))
buildAuthorizationProof jwt = runMaybeT $ do
  claims <- MaybeT $ getClaimsOf @"azure" jwt
  proofOfRole <- MaybeT $ pure $ hasAzureRole @"administrator" claims
  let proofOfSignature = conjure claims
      proofOfAuthorization =
        (proofOfSignature `introAnd` proofOfRole)
          `elimImpl` canDeleteApps
  return proofOfAuthorization
