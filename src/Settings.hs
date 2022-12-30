{-# LANGUAGE MultiParamTypeClasses #-}
{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DerivingStrategies #-}
{-# LANGUAGE KindSignatures #-}
{-# LANGUAGE AllowAmbiguousTypes #-}
{-# LANGUAGE DeriveGeneric #-}

module Settings where

import Data.Proxy

import Crypto.JWT

import GHC.TypeLits
import GHC.Generics

data Settings = Settings
  { azureJwtSettings :: JWTSettings
  , awsJwtSettings :: JWTSettings
  } deriving stock (Generic)

data JWTSettings = JWTSettings
  { validationSettings :: JWTValidationSettings
  , validationKeySet :: JWKSet
  } deriving stock (Generic)

class HasSettings (jwtSource :: Symbol) s where
  settings :: Proxy jwtSource -> s -> JWTSettings

instance HasSettings "azure" Settings where
  settings _ = azureJwtSettings

instance HasSettings "aws" Settings where
  settings _ = awsJwtSettings
