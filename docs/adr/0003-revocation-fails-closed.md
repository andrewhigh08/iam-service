# 0003. Token revocation model and fail-closed verification

Status: accepted

## Context

Stateless JWTs cannot be revoked by themselves. Logout, "logout everywhere", password change and
account blocking must take effect immediately, not when the access token expires.

## Decision

Two Redis-backed mechanisms, both checked on every authenticated request to this service:

1. A blacklist of individual `jti` values. An entry is kept until the token's `exp` plus the
   30 second clock-skew leeway that verification grants, so a replica with a slow clock cannot
   accept the token after the entry is gone. Each session records the `jti` of the access token
   issued with it, so `/auth/logout`, `DELETE /api/v1/sessions/:id` and refresh rotation blacklist
   that token together with the session.
2. A per-user instant "tokens issued before T are invalid". Set by logout-all, password change,
   blocking and refresh-token reuse: the instant is recorded first and every session of the user is
   deleted afterwards. The record is kept for the access token TTL plus one minute, so it outlives
   every token it covers and then expires on its own, and it is only ever moved forward: a replica
   with a lagging clock cannot re-validate tokens an earlier revocation covered. Blocking an already
   blocked user repeats this step, so a block whose Redis write failed can be retried. Both the
   instant and the `iat` claim have second resolution, so a token issued within the same second as
   the revocation is accepted only while its session is still live: every session that existed when
   the instant was recorded is deleted right after it, so a live one was opened later.

Verification fetches the blacklist entry and the instant in one pipelined Redis round trip; the
session lookup for the equal-second case is a second read that the common case never makes.

If Redis cannot answer, verification fails with 503. The service never accepts a token it could not
check against the revocation state. The same rule applies to the login lockout (ADR 0005). Redis must
run with `maxmemory-policy noeviction`: every key is a revocation, a session or a lockout, and an
evicted key fails open. The service checks the policy at startup and logs an error when it allows eviction.

Services that verify access tokens locally through JWKS never see either mechanism: a revoked token
stays valid for them until its `exp`, so `JWT_ACCESS_TOKEN_TTL` bounds that window.

## Consequences

- Revocation is immediate on this service and costs one pipelined Redis round trip per request in
  the common case.
- Redis is a hard dependency of the authenticated API. This is deliberate for an IAM: availability is
  not worth accepting revoked credentials.
- Redis data-loss window. A Redis restart without persistence drops the blacklist entries and the
  revocation instants together with the sessions: tokens revoked within the last access TTL become
  valid again until their `exp`, while the sessions are gone, so nobody can refresh and everyone is
  logged out. Mitigations: run Redis with AOF persistence (`appendonly yes`, `appendfsync everysec`
  or `always`) and keep the access TTL short, which bounds the window to `JWT_ACCESS_TOKEN_TTL`.
- Readiness reports Redis state, so an orchestrator stops routing traffic to an instance that lost it.
