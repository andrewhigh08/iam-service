# 0001. Ports and adapters layering, transactions carried in context

Status: accepted

## Context

The service talks to PostgreSQL, Redis and Casbin. Business rules (login, lockout, session
revocation, user lifecycle) must be testable without any of them, and the HTTP layer must stay
replaceable. An earlier revision declared this goal but let services import the Postgres package,
type-assert concrete repositories and pass `*gorm.DB` around to run transactions.

## Decision

- `internal/service` depends only on `internal/domain`, `internal/port` and `internal/pkg`.
  A unit test parses the package imports and fails if anything under `internal/adapter` appears.
- Every interface in `internal/port` is expressed in domain types. No GORM, Gin or go-redis types
  cross the boundary.
- Transactions are a port: `TxManager.WithinTx(ctx, fn)`. The Postgres implementation stores the
  transaction in the context; repositories read it back with a package-local helper and fall back to
  the pool connection. Nested calls reuse the outer transaction.
- Wiring lives in `internal/app`; `cmd/api/main.go` only parses configuration and handles signals.

## Consequences

- Services are unit-tested with generated mocks; the integration suite exercises the real adapters.
- Repositories cannot be used outside a service without a `TxManager`, which is intended.
- Adding a second storage backend means implementing the ports, nothing else changes.
