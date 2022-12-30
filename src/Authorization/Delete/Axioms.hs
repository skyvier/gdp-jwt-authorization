{-# LANGUAGE TypeOperators #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module Authorization.Delete.Axioms where

import Validation.SignedWith
import Authorization.HasRole
import Authorization.HasClaim

import GDP

data CanDeleteApplication token

azure ::
  Proof (
    (token `SignedBy` "azure" && (ClaimsOf token) `HasRole` "Orthanc.Plan.Delete")
    -->
    (CanDeleteApplication token)
  )
azure = axiom

aws ::
  Proof (
    (token `SignedBy` "aws" && HasExtraClaimValue (ClaimsOf token) "admin" "yes")
    -->
    (CanDeleteApplication token)
  )
aws = axiom
