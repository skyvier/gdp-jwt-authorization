{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module Authorization.Delete.Axioms where

import Validation.SignedWith

import Authorization.HasRole
import Authorization.HasClaim

import GDP

data CanDeleteApplication token

-- | A JSON web token authorizes the user to delete applications if
--
-- 1. the token is signed by Azure, and
-- 2. the claims of the token say that the user has an "administrator" role
azure ::
  Proof (
    (token `SignedBy` "azure" && (ClaimsOf token) `HasRole` "administrator")
    -->
    (CanDeleteApplication token)
  )
azure = axiom

-- | A JSON web token authorizes the user to delete applications if
--
-- 1. the token is signed by AWS, and
-- 2. the token contains an extra claim such that
--    - the key of the claim is "admin"
--    - the value of the claim is "yes"
aws ::
  Proof (
    (token `SignedBy` "aws" && HasExtraClaimValue (ClaimsOf token) "admin" "yes")
    -->
    (CanDeleteApplication token)
  )
aws = axiom
