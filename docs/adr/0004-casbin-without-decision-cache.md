# 0004. Casbin RBAC with in-memory enforcer and no Redis decision cache

Status: accepted

## Context

Authorization uses Casbin with policies persisted in PostgreSQL through the GORM adapter. An earlier
revision put a Redis cache of allow/deny decisions in front of the enforcer and described it as
"three-level caching".

## Decision

- The enforcer keeps the whole policy in memory; `Enforce` is a map lookup, far cheaper than a Redis
  round trip. The decision cache was removed.
- Role assignments and policies change through the service, which writes through the adapter with
  auto-save enabled.
- Multi-replica deployments can enable the Casbin Redis watcher (`AUTHZ_WATCHER_ENABLED=true`) so a
  policy change on one instance reloads the others. Single-instance deployments do not need it.

## Consequences

- One fewer moving part and no stale-decision window after a role change on the same instance.
- Without the watcher, a replica learns about policy changes only on restart; the flag is documented.
