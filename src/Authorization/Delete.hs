{-# LANGUAGE FlexibleContexts #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module Authorization.Delete
  ( CanDeleteApplication
  , canDeleteApplication

  , buildProofAzure
  , buildProofAws
  ) where

import Settings

import Validation.SignedWith

import Authorization.HasRole
import Authorization.HasClaim
import Authorization.Delete.Axioms (CanDeleteApplication)
import qualified Authorization.Delete.Axioms as Axiom

import GDP

import Crypto.JWT

import Control.Applicative ((<|>))

import Control.Monad.Reader
import Control.Monad.Time
import Control.Monad.Trans.Maybe

canDeleteApplication
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, HasSettings "aws" s, MonadIO m
     )
  => SignedJWT ~~ token
  -> m (Maybe (Proof (CanDeleteApplication token)))
canDeleteApplication token = do
  mAzureProof <- canDeleteApplicationAzure token
  mAwsProof   <- canDeleteApplicationAws token
  return $ mAzureProof <|> mAwsProof

canDeleteApplicationAzure
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "azure" s, MonadIO m
     )
  => SignedJWT ~~ token
  -> m (Maybe (Proof (CanDeleteApplication token)))
canDeleteApplicationAzure token = runMaybeT $ do
  claims <- MaybeT $ getClaimsOf @"azure" token
  let proofOfSignature = conjure claims
  proofOfRole <-
    MaybeT $ pure $ hasRole @"Orthanc.Plan.Delete" (exorcise claims)
  return $ buildProofAzure proofOfSignature proofOfRole

canDeleteApplicationAws
  :: ( Monad m, MonadTime m
     , MonadReader s m, HasSettings "aws" s, MonadIO m
     )
  => SignedJWT ~~ token
  -> m (Maybe (Proof (CanDeleteApplication token)))
canDeleteApplicationAws token = runMaybeT $ do
  claims <- MaybeT $ getClaimsOf @"aws" token
  let proofOfSignature = conjure claims
  proofOfClaimValue <-
    MaybeT $ pure $ hasExtraClaimWithValue @"admin" @"yes" (exorcise claims)
  return $ buildProofAws proofOfSignature proofOfClaimValue

buildProofAzure
  :: Proof (token `SignedBy` "azure")
  -> Proof ((ClaimsOf token) `HasRole` "Orthanc.Plan.Delete" )
  -> Proof (CanDeleteApplication token)
buildProofAzure proofOfSignature proofOfRole =
  (proofOfSignature `introAnd` proofOfRole) `elimImpl` Axiom.azure

buildProofAws
  :: Proof (token `SignedBy` "aws")
  -> Proof (HasExtraClaimValue (ClaimsOf token) "admin" "yes")
  -> Proof (CanDeleteApplication token)
buildProofAws proofOfSignature proofOfRole =
  (proofOfSignature `introAnd` proofOfRole) `elimImpl` Axiom.aws
