# AGENTS.md

Guidance for AI coding agents and new contributors working in this repository.

## What this is

`iam-service` is an Identity and Access Management microservice in Go:
JWT (RS256) authentication with refresh tokens, Casbin RBAC, PostgreSQL (GORM),
Redis (sessions, token revocation, login attempts), Prometheus metrics and
OpenTelemetry tracing. The HTTP layer is Gin.

## Layout

```
cmd/api/            entry point (flags, signals) - keep it thin
internal/app/       dependency wiring, router, graceful shutdown
internal/domain/    entities and domain constants, no external deps and no HTTP tags
internal/port/      interfaces between layers (services, repositories, stores, transactions)
internal/service/   business logic; depends only on domain, port and internal/pkg
internal/adapter/   infrastructure: http (gin handlers, middleware, DTOs), pgrepo (PostgreSQL), redisstore (Redis)
internal/config/    env configuration (cleanenv) and its validation
internal/pkg/       small shared packages (apperror, logger, metrics, telemetry, validator)
migrations/         SQL migrations, embedded and applied at startup
test/integration/   testcontainers-based tests against real Postgres and Redis
test/mocks/         generated gomock mocks (`make generate`)
docs/               swagger (generated) and ADRs
```

Dependency rule: `service` must not import anything from `adapter` (pinned by a test).
Transactions cross layers via `port.TxManager` and `context.Context`, never via `*gorm.DB`.
Repository writes are intent-specific (`UpdatePassword`, `SetBlocked`); never add a full-row update.

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

CI runs `go mod tidy -diff`, lint, unit and integration tests, gosec, govulncheck,
Docker build and Trivy. Keep all of it green.

## Conventions

- Code, comments and commit messages are in English. Documentation for users is in Russian (README).
- Commit messages follow Conventional Commits (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`, `chore:`).
- Errors cross layer boundaries as `*apperror.AppError`; HTTP handlers map them with `response.Error`.
- Security checks fail closed: when Redis cannot answer, token validation and the login lockout
  refuse the request (503) rather than proceed unprotected. Keep it that way.
- Use `any`, not `interface{}`.
- Every exported identifier has a doc comment. Do not comment what the code already says.
- New behaviour needs a unit test; anything touching Postgres or Redis also needs coverage in `test/integration`.
- Never commit secrets, `.env`, or files under `configs/keys/`.
- Do not hand-edit generated files (`test/mocks/`, `docs/swagger.*`, `docs/docs.go`).
