# Architecture decision records

Short records of the decisions that shape this service. One file per decision. An accepted record is
revised in place only so that it keeps describing the code accurately; when the decision itself
changes, a new numbered record supersedes the old one.

| # | Decision |
|---|----------|
| [0001](0001-ports-and-adapters.md) | Ports and adapters layering, transactions carried in context |
| [0002](0002-rs256-tokens-and-refresh-rotation.md) | RS256 access tokens, JWKS, hashed and rotated refresh tokens |
| [0003](0003-revocation-fails-closed.md) | Token revocation model and fail-closed verification |
| [0004](0004-casbin-without-decision-cache.md) | Casbin RBAC with in-memory enforcer and no Redis decision cache |
| [0005](0005-rate-limiting-and-lockout.md) | In-memory per-IP rate limiting plus per-account lockout |
| [0006](0006-gin-and-gorm.md) | Gin and GORM are kept, with restrictions |
