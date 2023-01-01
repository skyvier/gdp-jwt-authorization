# gdp-jwt-authorization

What is this repository all about?

> This is a PoC of using Ghosts of Departed Proofs (GDP) to have the compiler enforce
authorization checks for us

Authorization is an extremely business critical process. Getting it right is 
vital for the continuity of a business.

Nowadays, authorization claims are often carried in the claim set of a JWT.
The JWT is often issued by an identity provider and acquired via an OAuth 2.0 
authorization flow. Therefore, I chose to focus on JWTs in this PoC.

This repository explores how to bring the authorization claims from the term
level to the type level so that GHC can enforce authorization checks for
certain protected functionalities. Bridging the gap between term and type
levels can be accomplished with multiple techniques (such as dependent types)
but I chose to use a technique called The Ghosts of Departed Proofs (GDP).

Ghosts of Departed Proofs was introduced by Matt Noonan in a paper with the
same name and he wrote an auxiliary Haskell library, called `gdp`, for those
who want to write GDP-style libraries. That library is used extensively in this
repository.

I recommend reading [the paper] and checking out the documentation of [gdp].

[gdp]: https://hackage.haskell.org/package/gdp-0.0.3.0
[the paper]: https://iohk.io/en/research/library/papers/ghosts-of-departed-proofs-functional-pearls/

## The problem

Let us assume that you are writing a program that receives JWTs from multiple
identity providers (e.g. `AWS Directory Service` and `Azure Active Directory`)
and the claim set from those `IdP`s are not quite homogenous.

For example, the JWT of a user with admin privileges issued by Azure would look
something like this:

```
Token header
------------
{
  "typ": "JWT",
  "alg": "RS256",
  "kid": "abc"
}

Token claims
------------
{
  "aud": "<your-application>",
  "iat": 1672433284,
  "sub": "<your-username>",
  "roles": [
    "administrator"
  ]
}

```

But the JWT of a user with admin privileges issued by AWS would look like this:

```
Token header
------------
{
  "typ": "JWT",
  "alg": "HS512"
}

Token claims
------------
{
  "iat": 1669217013.5449486,
  "sub": "<your-username>",
  "aud": "<your-application>",
  "admin": "yes"
}
```


Let's assume we are not in control of the format of the JWTs.


Given that you receive a JWT from the user as input, how would you write a
function that can only be run if the user

* is an administrator according to Azure?
* is an administrator according to AWS?
* is an administrator according to either Azure or AWS?

### This repository 

The code in this repository is a working PoC of the techniques described 
in the rest of this document.

It implements a program that allows a user to "delete an application" if the
JWT provided by the user tells that the user is an administrator according to
Azure or AWS.

### Naive solution 

In the naive solution, you would write primitive functions for checking

1. that a JWT is issued by the expected identity provider
2. that the claims of the JWT are valid 
   - the JWT has not yet expired 
   - the JWT was intended for your application
   - etc.
2. that a JWT contains claims that proof that the user can perform 
administrator tasks

The primitive functions would look something like this:

``` haskell
-- Verify that 
--   1. the JWT was signed with a key in a 'JWKSet'
--   2. the extracted claims are valid 
-- and return the claims
extractClaims :: JWKSet -> SignedJWT -> Either VerificationError ClaimsSet
extractClaims keys = 
  verifySignatureWith keys >=> validateClaims

-- Check whether or not the 'ClaimsSet' of a JWT issued by Azure describes an
-- administrator.
hasAdministratorClaimAzure
  :: ClaimsSet -> Bool
hasAdministratorClaimAzure claims =
  let mRolesClaim = getClaim "roles" claims
  in maybe False ("administrator" `elem`) mRolesClaim

-- Check whether or not the 'ClaimsSet' of a JWT issued by AWS describes an 
-- administrator.
hasAdministratorClaimAws
  :: ClaimsSet -> Bool 
hasAdministratorClaimAws claims = 
  let mAdminClaim = getClaim "admin" claims
  in maybe False (== "yes") mAdminClaim
```

and then you could use the primitive functions to check whether or not a user 
is authorized to perform administrator tasks based on the JWT 

``` haskell
isAuthorizedByAzure :: SignedJWT -> Either VerificationError Bool 
isAuthorizedByAzure token = do 
  claims <- extractClaims azureKeySet token
  return $ hasAdministratorClaimAzure claims

isAuthorizedByAws :: SignedJWT -> Either VerificationError Bool 
isAuthorizedByAws token = do 
  claims <- extractClaims awsKeySet token
  return $ hasAdministratorClaimAws claims

isAuthorizedByEither :: SignedJWT -> Either [VerificationError] Bool
isAuthorizedByEither token =
  let results = [isAuthorizedByAzure token, isAuthorizedByAws token]

      errors    = lefts results
      mDecision = headMay $ rights results

  in maybe (Left errors) Right mDecision

throwVerificationError :: Either VerificationError Bool -> IO Bool
throwVerificationError result =
  either throwIO return result

throwUnauthorized :: Either VerificationError Bool -> IO ()
throwUnauthorized result =
  case result of 
    Left error  -> 
      throwIO error
    Right False ->
      throwIO Unauthorized
    Right True  -> pure ()
```

These authorization checks could then be placed before running protected
functions, like

``` haskell
handler :: SignedJWT -> IO ()
handler token = do 
  throwUnauthorized $ isAuthorizedByAzure token
  fireMissiles
  soundTheAlarm

-- | Allowed only for users that are administrators according to Azure.
fireMissiles :: IO ()
fireMissiles = boom

-- | Allowed only for users that are administrators according to Azure.
soundTheAlarm :: IO ()
soundTheAlarm = piipaa
```

or inside those protected functions:

``` haskell
handler :: IO ()
handler = do 
  fireMissiles 
  soundTheAlarm

-- | Allowed only for users that are administrators according to Azure.
fireMissiles :: SignedJWT -> IO ()
fireMissiles = do
  throwUnauthorized $ isAuthorizedByAzure token
  boom

-- | Allowed only for users that are administrators according to Azure.
soundTheAlarm :: SignedJWT -> IO ()
soundTheAlarm = do
  throwUnauthorized $ isAuthorizedByAzure token
  piipaa
```

#### Flaws

The naive solution suffers from multiple flaws:

1. Unsafety
   - It's way too easy to forget to perform an authorization check when one 
     is needed
2. Redundancy
   - In complex tasks, one could easily end up performing the authorization 
     check multiple times (see the previous code block) even though it's
     already clear the the user has the necessary authorization
3. Boolean blindness 
   - The results of `isAuthorized` functions are bare `Bool`s which tell
     nothing about the meaning of the bit
4. Disconnect between a token, the claims of the token and the authorization
   provided by the token (from the compilers point of view)
   - The `SignedJWT` received from the user is in no way connected to the 
     `ClaimsSet` that is extracted from it 
   - Neither the `SignedJWT` nor the `ClaimsSet` are in any way connected to
     the authorization result carried inside the token (`Bool`)

##### Unsafety 

An example of the unsafety of the naive solution:

``` haskell
handler :: SignedJWT -> IO ()
handler token = do 
  throwUnauthorized $ isAuthorizedByAzure token
  fireMissiles
  soundTheAlarm

-- ### Unsafety
-- 
-- The developer of the new handler forgets to perform the authorization 
-- check even though the function performs a protected task.
newHandler :: SignedJWT -> IO () 
newHandler token = do 
  doSomething
  fireMissiles
  doSomethingElse

-- | Allowed only for users that are administrators according to Azure.
fireMissiles :: IO ()
fireMissiles = boom

-- | Allowed only for users that are administrators according to Azure.
soundTheAlarm :: IO ()
soundTheAlarm = piipaa
```

This kind of a bug should be caught by the compiler.

##### Redundancy

The unsafety of the previous example is greatly mitigated by putting the 
authorization checks inside the protected functions but that comes with its own 
downside, redundancy.

``` haskell
handler :: IO ()
handler = do 
  fireMissiles 
  soundTheAlarm

-- | Allowed only for users that are administrators according to Azure.
fireMissiles :: SignedJWT -> IO ()
fireMissiles = do
  throwUnauthorized $ isAuthorizedByAzure token
  boom

-- | Allowed only for users that are administrators according to Azure.
soundTheAlarm :: SignedJWT -> IO ()
soundTheAlarm = do
  -- ### Redundancy
  -- 
  -- This authorization check is clearly redundant in the use case of 
  -- 'handler'.
  throwUnauthorized $ isAuthorizedByAzure token
  piipaa
```

The developer should be able to obtain a proof of the authorization check from 
`isAuthorizedByAzure`. He could then safely reuse that proof in `soundTheAlarm`.

##### Boolean blindness

Technically, the current primitive functions allow reusing a "proof" of 
authorization but that proof is carried in a boolean value. That leaves the
design fatally vulnerable to boolean blidness.

``` haskell
handler :: IO ()
handler = do 
  azureAuthorizationProof <- 
    throwVerificationError $ isAuthorizedByAzure token

  fireMissiles azureAuthorizationProof
  soundTheAlarm azureAuthorizationProof

  -- ### Boolean blindness
  --
  -- 'destroyAmazonVMs' accepts proof of authorization from Azure even though 
  -- it expects authorization from AWS
  destroyAmazonVMs azureAuthorizationProof

-- | Allowed only for users that are administrators according to Azure.
fireMissiles 
  :: Bool 
  -- ^ Tells whether or not the user is authorized by Azure
  -> IO ()
fireMissiles True  = boom
fireMissiles False = throwIO Unauthorized

-- | Allowed only for users that are administrators according to Azure.
soundTheAlarm 
  :: Bool 
  -- ^ Tells whether or not the user is authorized by Azure
  -> IO ()
soundTheAlarm True  = piipaa
soundTheAlarm False = throwIO Unauthorized

-- | Allowed only for users that are administrators according to AWS.
destroyAmazonVMs 
  :: Bool 
  -- ^ Tells whether or not the user is authorized by AWS
  -> IO ()
destroyAmazonVMs True  = destroyThem
destroyAmazonVMs False = throwIO Unauthorized
```

##### General disconnect between tokens, claims and proofs

It would have been very easy to make a fundamental mistake in our primitive 
authorization functions. Can you spot the issue in the following code snippet?

``` haskell 
isAuthorizedByAzure :: SignedJWT -> Either VerificationError Bool 
isAuthorizedByAzure token = do 
  claims <- extractClaims awsKeySet token
  return $ hasAdministratorClaimAzure claims

isAuthorizedByAws :: SignedJWT -> Either VerificationError Bool 
isAuthorizedByAws token = do 
  claims <- extractClaims awsKeySet token
  return $ hasAdministratorClaimAws claims
```

A fundamental issue like that should have been caught by the compiler.

### Proposed solution

You probably noticed that the word "proof" was ubiquitous in the previous
chapter. Good authorization is all about propagating proofs that authorization
has been checked. 

The proofs can be propagated in many ways. The naive solution allowed for 
propagating proofs of authorization checks as boolean at the term level. The
compiler allowed us to do all kinds of stupid mistakes.

If we bring a bit more information about authorization to the type level, we
can force the compiler to enforce some sanity checks on our code.

The simplest possible approach uses techniques like `newtype` wrappers on top
of booleans and smart constructors for those newtypes.

I have been playing around with the `gdp` library lately and authorization
seemed like a fun way to apply the tools introduced by the library. Applying a
Ghost of Departed Proofs style to the described problem results in an
authorization API that solves all of the flaws of the naive solution and also
results in some pretty elegant code (in my humble opinion).

#### Overview

> :warning: **The following section assumes some familiarity with the GDP library**

The features provided by the `gdp` library make it easy to 

1. name objects (values and functions)
2. create proofs about named objects
3. attach proofs to values

GDP makes it easy to translate a statement like 

> This specific JWT token is signed by Azure

to a type level signature such as 

``` haskell
SignedJWT ~~ token ::: (token `SignedBy` "azure")
```

which can be read as follows:

> SignedJWT named token such that token is signed by Azure

Line by line, the type signature can interpreter like this:

``` haskell
SignedJWT                     -- SignedJWT
  ~~                          -- "named"
  token                       -- token
  :::                         -- "such that"
  (token `SignedBy` "azure")  -- token is signed by Azure
```

Proofs can be easily detached/attached with named values.

```
(...)    :: a -> Proof p -> a ::: p
conjure  :: (a ::: p) -> Proof p 
exorcise :: (a ::: p) -> a
```

##### How are the proofs created?

A function within a module can check whether or not a JWT is signed by Azure.
If the token is signed by Azure, the function returns a proof about that 
statement.

``` haskell
module Validation.SignedWith (SignedBy, isSignedBy) where

data SignedBy token (signedName :: Symbol)

isSignedBy 
  :: forall signerName token. KnownSymbol signerName
  => SignedJWT ~~ token 
  -> Maybe (Proof (token `SignedBy` signerName))
isSignedBy = undefined
```

It's also possible to extract the claims of a `SignedJWT` and maintain a
connection between the `SignedJWT` and its `ClaimsSet` at the type level:

``` haskell 
module Validation.SignedWith (ClaimsOf, getClaimsOf) where

newtype ClaimsOf token = ClaimsOf Defn

getClaimsOf
  :: forall signerName token. KnownSymbol signerName
  => SignedJWT ~~ token 
  -> Maybe (ClaimsSet ~~ ClaimsOf token)
getClaimsOf = undefined
```

The function `isSignedBy` is the only available method of creating a value of 
type ``Proof (token `SignedBy` signerName)`` for the clients of this package.


The function `getClaimsOf` is the only available way to acquire a `ClaimsSet`
attached to a specific JWT via the `ClaimsOf token` name.


As long as the functions themselves have been implemented correctly and tested 
extensively, you can always trust that the proofs describe reality. 


Proofs can also be generated from other proofs via axioms. The following axiom
(`azureAdmin`) states that 

> If you can prove that the token is signed by Azure **and** that the claims 
> of the token have a role called "administrator", you have proved that the
> token describes an administrator according to Azure.

``` haskell
data IsAzureAdministrator token

azureAdmin ::
  Proof (
    (token `SignedBy` "azure" && (ClaimsOf token) `HasRole` "administrator")
    -->
    (IsAdministrator token)
  )
azureAdmin = axiom
```

Essentially, you can generate a `Proof (IsAdministrator token)` from two other
proofs

``` haskell 
buildProofAzureAdmin
  :: Proof (token `SignedBy` "azure")
  -> Proof ((ClaimsOf token) `HasRole` "administrator" )
  -> Proof (IsAzureAdministrator token)
buildProofAzureAdmin proofOfSignature proofOfRole =
  (proofOfSignature `introAnd` proofOfRole) `elimImpl` azureAdmin
```

##### How can the proofs be used?

You can then use the proofs in the type signatures of other function to limit
the domain of a function.

For example, you could write a function that only accepts JWTs signed by Azure:

``` haskell 
getAzureClaims
  :: forall token. SignedJWT ~~ token ::: (token `SignedBy` "azure")
  -> ClaimsSet ~~ ClaimsOf token ::: (token `SignedBy` "azure")
getAzureClaims = undefined
```

Or you could write a function that can only be run if you can prove that a JWT 
describes an administrator according to Azure. Rewriting an example from the
naive implementation:

``` haskell
-- | Allowed only for users that are administrators according to Azure.
fireMissiles 
  :: Proof (IsAzureAdministrator token)
  -- ^ Tells whether or not the user is an administrator according to Azure
  -> IO ()
fireMissiles _ = boom
```

The domain of the function is now restricted in such a way that you are only 
able to run it if you are able to provide a proof that the token is authorized
to fire missiles (since it describes an administrator user).

It is now impossible to run `fireMissiles` without providing a proof of 
authorization. The compiler just doesn't let you do that.

##### Have the issues of the naive solution been solved?

Yes. The original issues were:

1. Unsafety
   - It's way too easy to forget to perform an authorization check when one 
     is needed
2. Redundancy
   - In complex tasks, one could easily end up performing the authorization 
     check multiple times (see the previous code block) even though it's
     already clear the the user has the necessary authorization
3. Boolean blindness 
   - The results of `isAuthorized` functions are bare `Bool`s which tell
     nothing about the meaning of the bit
4. Disconnect between a token, the claims of the token and the authorization
   provided by the token (from the compilers point of view)
   - The `SignedJWT` received from the user is in no way connected to the 
     `ClaimsSet` that is extracted from it 
   - Neither the `SignedJWT` nor the `ClaimsSet` are in any way connected to
     the authorization result carried inside the token (`Bool`)

How they were fixed?

1. Unsafety 
   - It's no longer possible to perform a protected function without providing 
     proof of authorization (as long as the domain of the protected function is 
     restricted).
2. Redundancy 
   - Proof of authorization can be obtained once and reused as many times as 
     needed.
   - Proofs from previous checks can be used to construct new proofs via axioms
3. Boolean blindness 
   - We're no longer dealing with boolean. We're dealing with clearly named 
     proofs of statements.
4. Disconnect between a token, the claims of the token and the authorization
   provided by the token (from the compilers point of view)
   - Every token has a unique name (`SignedJWT ~~ token`)
   - The claims of a token have a name that is attached to the name of the token 
     they were extracted from (`ClaimsSet ~~ ClaimsOf token`)
   - Proofs of authorization are also attached to the name of the token 
     - `IsAzureAdministrator token`

## What about servant-auth?

Yes, [servant-auth] and [servant-auth-server] can solve some of the problems
described here but not all. Also, the technique introduced in this repository
can be integrated with [servant-auth].

The techniques described in this repository can be applied to any web server
that receives JWTs for authorization - not just web servers implemented with 
`servant`.

[servant-auth]: https://hackage.haskell.org/package/servant-auth
[servant-auth-server]: https://hackage.haskell.org/package/servant-auth-server

## What about singletons (or other dependent types libraries)?

I find GDP to be a much simpler technique.
