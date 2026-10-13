# Architecture decision records

Short records of the decisions that shape this service. One file per decision, never edited after
acceptance; a superseding decision gets a new number.

| # | Decision |
|---|----------|
| [0001](0001-ports-and-adapters.md) | Ports and adapters layering, transactions carried in context |
| [0002](0002-rs256-tokens-and-refresh-rotation.md) | RS256 access tokens, JWKS, hashed and rotated refresh tokens |
| [0003](0003-revocation-fails-closed.md) | Token revocation model and fail-closed verification |
| [0004](0004-casbin-without-decision-cache.md) | Casbin RBAC with in-memory enforcer and no Redis decision cache |
| [0005](0005-rate-limiting-and-lockout.md) | In-memory per-IP rate limiting plus per-account lockout |
