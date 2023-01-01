{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE LambdaCase #-}

module App.Delete where

import Settings
import Validation.SignedWith
import Authorization.HasRole
import Authorization.Delete

import Control.Monad.Reader
import Control.Monad.Time

import GDP

import Crypto.JWT

deleteApplication
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, HasSettings "aws" s, MonadIO m
     )
  => SignedJWT
  -> m ()
deleteApplication jwt =
  name jwt $ \namedJwt -> do
    mProof <- canDeleteApplication namedJwt
    case mProof of
      Just proof -> deleteApplicationSafe proof
      Nothing -> liftIO $ putStrLn "Unauthorized"

deleteApplicationAzure
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, MonadIO m
     )
  => SignedJWT
  -> m ()
deleteApplicationAzure jwt =
  name jwt $ \namedJwt ->
    withClaimsSignedBy @"azure" namedJwt $ \(namedClaims, proofOfSignature) ->
      withRole @"administrator" namedClaims $ \proofOfRole ->
        let proof = buildProofAzure proofOfSignature proofOfRole
        in deleteApplicationSafe proof

deleteApplicationSafe
  :: MonadIO m
  => Proof (CanDeleteApplication token)
  -> m ()
deleteApplicationSafe _ = liftIO $ putStrLn "Done"
