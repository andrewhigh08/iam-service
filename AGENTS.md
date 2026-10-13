# AGENTS.md

Guidance for AI coding agents and new contributors working in this repository.

## What this is

`iam-service` is an Identity and Access Management microservice in Go:
JWT (RS256) authentication with refresh tokens, Casbin RBAC with policies kept in PostgreSQL
through a small in-house adapter, PostgreSQL (GORM), Redis (sessions, token revocation, login
attempts), Prometheus metrics and OpenTelemetry tracing. The HTTP layer is Gin.

## Layout

```
cmd/api/            entry point: config, signals, app.Run - keep it thin
internal/app/       dependency wiring, router, graceful shutdown
internal/domain/    entities and domain constants, no external deps and no HTTP tags
internal/port/      interfaces between layers (services, repositories, stores, transactions)
internal/service/   business logic; depends only on domain, port, internal/pkg and the casbin enforcer interface
internal/adapter/   infrastructure: http (gin handlers, middleware, DTOs), pgrepo (PostgreSQL),
                    redisstore (Redis), casbinpg (Casbin policies in the casbin_rule table)
internal/config/    env configuration (cleanenv) and its validation
internal/pkg/       small shared packages (apperror, logger, metrics, telemetry, validator)
configs/            Casbin model, Prometheus and Grafana configuration; RSA keys go to configs/keys (never committed)
migrations/         SQL migrations, embedded and applied at startup
test/integration/   testcontainers-based tests against real Postgres and Redis
test/mocks/         generated gomock mocks (`make generate`)
docs/               swagger (generated) and ADRs
```

Dependency rule: `service` must not import anything from `adapter` (pinned by a test).
Transactions cross layers via `port.TxManager` and `context.Context`, never via `*gorm.DB`;
repositories join the transaction found in the context and otherwise run on the pool, so anything
that must be atomic is wrapped in `WithinTx` by the service.
Repository writes are intent-specific (`UpdatePassword`, `SetBlocked`); never add a full-row update.
Health checks reach PostgreSQL and Redis through a `Pinger` interface, not through driver types.
Casbin policies are persisted by `internal/adapter/casbinpg`; do not bring `casbin/gorm-adapter`
back, it links MySQL, SQL Server, ClickHouse and SQLite drivers into the binary.

## Commands

```
make help              list targets
make run               run the API locally (expects Postgres and Redis, see .env.example)
make up / make down    full stack via docker compose (API, Postgres, Redis, Prometheus, Grafana, Jaeger)
make test              unit tests with race detector
make test-integration  integration tests (needs Docker)
make lint              golangci-lint (config in .golangci.yml, v2 format)
make generate          regenerate mocks and swagger docs after changing interfaces or handlers
make build             static binary in bin/
```

CI runs `go mod tidy -diff`, a generated-code freshness check, lint, unit and integration tests,
gosec, govulncheck, Docker build and Trivy. gosec (high severity and confidence findings) and Trivy
(unfixed CRITICAL/HIGH vulnerabilities in the image) block the image publish; govulncheck is
advisory. Keep all of it green.

## Conventions

- Code, comments and commit messages are in English. Documentation for users is in Russian (README).
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`, `chore:`).
- Errors cross layer boundaries as `*apperror.AppError`; HTTP handlers map them with `response.Error`.
- Security checks fail closed: when Redis cannot answer, token validation and the login lockout
  refuse the request (503) rather than proceed unprotected. Keep it that way.
- Login answers a blocked account exactly like a wrong password ("invalid credentials") and audits
  the reason; only `/auth/refresh` and the authenticated password change say "account is blocked".
- Never log passwords, tokens or hashes.
- Use `any`, not `interface{}`.
- Every exported identifier has a doc comment. Do not comment what the code already says.
- New behaviour needs a unit test; anything touching Postgres or Redis also needs coverage in `test/integration`.
- Never commit secrets, `.env`, or files under `configs/keys/`.
- Do not hand-edit generated files (`test/mocks/`, `docs/swagger.*`, `docs/docs.go`).
