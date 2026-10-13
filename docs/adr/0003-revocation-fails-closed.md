# 0003. Token revocation model and fail-closed verification

Status: accepted

## Context

Stateless JWTs cannot be revoked by themselves. Logout, "logout everywhere", password change and
account blocking must take effect immediately, not when the access token expires.

## Decision

Two Redis-backed mechanisms, both checked on every authenticated request:

1. A blacklist of individual `jti` values, kept until the token would expire anyway. Each session
   records the `jti` of the access token issued with it, so `/auth/logout`, `DELETE /api/v1/sessions/:id`
   and refresh rotation blacklist that token together with the session.
2. A per-user instant "tokens issued before T are invalid". Set by logout-all, password change,
   blocking and refresh-token reuse, after every session of the user has been deleted. Kept for the
   access token lifetime, so it expires on its own, and only ever moved forward: a replica with a
   lagging clock cannot re-validate tokens an earlier revocation covered. Blocking an already blocked
   user repeats this step, so a block whose Redis write failed can be retried. Both the instant and the `iat` claim have second resolution, so a token
   issued within the same second as the revocation is accepted only while its session is still
   live: every session that existed at the instant was already gone, so a live one is newer.

If Redis cannot answer, verification fails with 503. The service never accepts a token it could not
check against the revocation state. The same rule applies to the login lockout (ADR 0005). Redis must
run with `maxmemory-policy noeviction`: every key is a revocation, a session or a lockout, and an
evicted key fails open. The service checks the policy at startup and logs an error when it allows eviction.

## Consequences

- Revocation is immediate and costs two Redis reads per request.
- Redis is a hard dependency of the authenticated API. This is deliberate for an IAM: availability is
  not worth accepting revoked credentials. Operators should run Redis with persistence or accept that a
  restart logs everyone out.
- Readiness reports Redis state, so an orchestrator stops routing traffic to an instance that lost it.
