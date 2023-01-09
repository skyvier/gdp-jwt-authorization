{-# LANGUAGE DataKinds #-}
{-# LANGUAGE TypeOperators #-}
module Authorization.Axioms where

import Validation.IssuedBy
import Validation.Azure.HasRole

import GDP

data CanViewApps token

canViewApps ::
  Proof (
    ((token `IssuedBy` "azure") || (token `IssuedBy` "okta"))
    -->
    (CanViewApps token)
  )
canViewApps = axiom

data CanDeleteApps token

canDeleteApps ::
  Proof (
    (token `IssuedBy` "azure" && (ClaimsOf token) `HasAzureRole` "administrator")
    -->
    (CanDeleteApps token)
  )
canDeleteApps = axiom
