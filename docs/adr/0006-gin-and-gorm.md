# 0006. Gin and GORM are kept, with restrictions

Status: accepted

## Context

The service was written on Gin and GORM. Since Go 1.22 the standard `net/http` router matches
methods and path patterns, and pgx with sqlc gives typed, compile-time checked SQL without an ORM.
Both were considered as replacements during the rebuild around ports and adapters (ADR 0001).

## Decision

Gin and GORM stay, for this service, for the following reasons.

- Both live entirely inside adapters. Handlers, middleware and DTOs are in `internal/adapter/http`,
  repositories in `internal/adapter/pgrepo` and the policy adapter in `internal/adapter/casbinpg`;
  no Gin or GORM type crosses a port. Replacing either is an adapter rewrite, not a redesign, so the
  decision can be revisited without touching the services.
- Gin brings what the HTTP layer needs ready-made: route groups with per-group middleware, path
  parameters, JSON binding with validator tags, `SetTrustedProxies` for client IP resolution, and
  maintained integrations for OpenTelemetry (`otelgin`), CORS and the Swagger UI.
- GORM is used as a thin query builder and transaction helper: `Transaction` with rollback on error
  and panic, `TranslateError` for unique-violation detection, parameter redaction in its logs, and
  the OpenTelemetry plugin for query spans.

What is deliberately not used:

- No GORM associations, hooks or preloading. Entities in `internal/domain` carry column tags only
  and are loaded and written explicitly.
- No `AutoMigrate`. The schema, including the `casbin_rule` table, lives in `migrations/` as SQL
  and is applied by golang-migrate at startup.
- No full-row updates. Every write names its columns explicitly and is intent-specific, such as
  `UpdatePassword` or `SetBlocked`; a repository never saves a whole entity it did not just create.
- No GORM in services or ports; the transaction travels in the context (ADR 0001).

## Consequences

- Known downsides: the `net/http` 1.22 router would cover the routing and drop a dependency with
  its own context type and binding rules; pgx with sqlc would be lighter, keep the SQL visible and
  check it at compile time, and remove GORM's reflection and the implicit behaviour (zero-value
  handling, soft-delete conventions) that the code has to opt out of.
- The restrictions above keep the migration path open: with explicit column lists and SQL
  migrations, a repository can be rewritten on pgx one at a time behind the same port.
- Contributors keep the restrictions; AGENTS.md repeats them.
