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

TODO: let's assume we are not in control of the format of the JWTs.

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

TODO!

### Proposed solution

TODO!

## What about servant-auth?

Yes, [servant-auth] and [servant-auth-server] can solve some of the problems
described here but not all. Also, the technique introduced in this repository
can be integrated with [servant-auth].

The techniques described in this repository can be applied to any web server
that receives JWTs for authorization - not just web servers implemented with 
`servant`.

[servant-auth]: https://hackage.haskell.org/package/servant-auth
[servant-auth-server]: https://hackage.haskell.org/package/servant-auth-server
