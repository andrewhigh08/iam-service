# 0002. RS256 access tokens, JWKS, hashed and rotated refresh tokens

Status: accepted

## Context

Other services need to verify access tokens without calling the IAM on every request, and a leaked
refresh token must not grant indefinite access.

## Decision

- Access tokens are JWTs signed with RS256. Only this service holds the private key; the public key
  is published at `/.well-known/jwks.json` with a stable `kid`.
- Verification pins the algorithm to RS256 and requires `exp`, `iat` and `iss`. Tokens carry `jti`
  (for blacklisting) and `sid` (the session they belong to).
- Refresh tokens are 32 random bytes. Redis stores only `sha256(token)` together with the user id,
  creation time, IP and user agent. The session id shown to users is a prefix of that hash.
- `/auth/refresh` rotates: the presented token is consumed in one atomic Redis script and a new
  pair is issued, so a token presented twice at the same moment yields exactly one session. The
  consumed hash is remembered for the refresh TTL; a later presentation of it is reuse detection:
  the request is rejected and every session of the user is revoked, because either the legitimate
  client or a thief holds the successor.
- The session start time survives rotation and bounds the chain: a session older than
  `JWT_SESSION_MAX_AGE` cannot be refreshed again, and a session that started before the user's
  last password change is rejected as well.

## Consequences

- Access tokens are short-lived (15 minutes by default); revocation is handled separately (ADR 0003).
- A database dump of Redis does not reveal usable refresh tokens.
- Clients must always store the refresh token returned by the last refresh call; retrying a refresh
  whose response was lost logs the user out everywhere, which is the intended trade-off.
- Verification tolerates 30 seconds of clock skew between replicas; keys shorter than 2048 bits are refused.
