# 0001. Ports and adapters layering, transactions carried in context

Status: accepted

## Context

The service talks to PostgreSQL, Redis and Casbin. Business rules (login, lockout, session
revocation, user lifecycle) must be testable without any of them, and the HTTP layer must stay
replaceable. An earlier revision declared this goal but let services import the Postgres package,
type-assert concrete repositories and pass `*gorm.DB` around to run transactions.

## Decision

- `internal/service` depends only on `internal/domain`, `internal/port` and `internal/pkg`, plus
  the casbin enforcer interface in the authorization service. A unit test parses the package
  imports and fails if anything under `internal/adapter` appears.
- Every interface in `internal/port` is expressed in domain types. No GORM, Gin or go-redis types
  cross the boundary. One deliberate exception: `port.Claims` embeds `jwt.RegisteredClaims`. The
  registered claims and their validation rules are the JWT standard itself, not an adapter detail,
  and a private copy of the struct would only be mapped back at the boundary.
- Transactions are a port: `TxManager.WithinTx(ctx, fn)`. The PostgreSQL implementation
  (`internal/adapter/pgrepo`) stores the transaction in the context; repositories join the
  transaction found in the context and otherwise run on the pool, so the atomicity of several
  repository calls depends on the service wrapping them in `WithinTx`. Nested calls reuse the outer
  transaction.
- Wiring lives in `internal/app`; `cmd/api/main.go` only loads the configuration, handles signals
  and calls `app.Run`.

## Consequences

- Services are unit-tested with generated mocks; the integration suite exercises the real adapters
  (`pgrepo`, `redisstore`, `casbinpg`).
- A repository call made outside `WithinTx` is a single auto-committed statement. That is intended
  for reads and single writes and wrong for anything that must be atomic, so every multi-step
  service operation is reviewed for the wrapper.
- Adding a second storage backend means implementing the ports, nothing else changes.
