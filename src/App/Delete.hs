{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE DataKinds #-}

module App.Delete where

import Settings
import Validation.SignedWith
import Authorization.HasRole

import Control.Monad.Reader
import Control.Monad.Time

import GDP

import Crypto.JWT

deleteApplication
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, MonadIO m
     )
  => SignedJWT
  -> m ()
deleteApplication jwt =
  name jwt $ \namedJwt ->
    withClaimsSignedBy @"azure" namedJwt $ \claims ->
      withRole @"Orthanc.Plan.Delete" claims $ \claimsWithRole ->
        deleteApplicationSafe claimsWithRole

deleteApplicationSafe
  :: MonadIO m
  => (ClaimsSet ~~ claims ::: HasRole "Orthanc.Plan.Delete" claims)
  -> m ()
deleteApplicationSafe _ = liftIO $ putStrLn "Done"
