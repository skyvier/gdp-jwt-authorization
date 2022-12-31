# gdp-jwt-authorization

What is this all about?

> Using Ghosts of Departed Proofs (GDP) to have the compiler enforce
authorization checks for us

Authorization is an extremely business critical process. Getting it right is 
vital for the continuity of a business.

Nowadays, authorization claims are often carried in the claim set of a JWT.
The JWT is often issued by an identity provider via an OAuth 2.0 authorization
flow. Therefore, I chose to focus on JWTs.

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

> :warning: **The following section assumes familiarity with the GDP library**



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
