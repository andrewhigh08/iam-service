# 0004. Casbin RBAC with in-memory enforcer and no Redis decision cache

Status: accepted

## Context

Authorization uses Casbin with policies persisted in PostgreSQL. An earlier revision loaded them
through `github.com/casbin/gorm-adapter`, which linked the MySQL, SQL Server, ClickHouse and SQLite
drivers into the binary of a service that only ever talks to PostgreSQL, and put a Redis cache of
allow/deny decisions in front of the enforcer described as "three-level caching".

## Decision

- Policies are persisted by a small in-house adapter, `internal/adapter/casbinpg`: about a hundred
  lines over the `casbin_rule` table that the embedded migrations own. The gorm-adapter dependency
  and the drivers it pulled in are gone from the binary.
- The enforcer keeps the whole policy in memory; `Enforce` is an in-memory evaluation of the loaded
  policy, far cheaper than a Redis round trip. The decision cache was removed.
- Role assignments and policies change through the service, which writes through the adapter with
  auto-save enabled.
- Multi-replica deployments can enable the Casbin Redis watcher (`AUTHZ_WATCHER_ENABLED=true`) so a
  policy change on one instance reloads the others. Single-instance deployments do not need it.

## Consequences

- One fewer moving part and no stale-decision window after a role change on the same instance.
- The adapter supports exactly what this service does with policies; a feature it lacks is added
  here rather than by bringing a generic adapter and its drivers back.
- Without the watcher, a replica learns about policy changes only on restart; the flag is documented.
