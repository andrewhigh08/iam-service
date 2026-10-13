# 0005. In-memory per-IP rate limiting plus per-account lockout

Status: accepted

## Context

Login endpoints must resist credential stuffing and brute force without making the service depend
on an external gateway.

## Decision

- A token-bucket limiter per client, kept in process memory behind a mutex, with a janitor that
  evicts idle entries and a cap on the number of entries. IPv4 clients are keyed by address, IPv6
  clients by their /64 prefix, so rotating addresses inside one prefix does not buy fresh buckets.
  Stricter buckets apply to `/auth/login`, `/auth/change-password` and `/api/v1/change-password`.
- Independently of the IP, each account accumulates failed attempts in Redis; after
  `LOCKOUT_MAX_ATTEMPTS` the account is locked for `LOCKOUT_DURATION`, and a successful credential
  check resets the counter. A wrong current password on `/api/v1/change-password` counts like a
  failed login, so a stolen access token cannot be used to guess the password.
- The lockout fails closed: when Redis cannot report or record the state, the credential check
  answers 503 instead of proceeding uncounted.
- Login answers a blocked account exactly like a wrong password ("invalid credentials"), so the
  response reveals neither whether the account exists nor whether it is blocked; the audit entry
  records the reason. `/auth/refresh` and the authenticated password change say "account is
  blocked", because the caller has already proven possession of a valid credential.
- Client IP comes from the socket unless the request arrives from an address listed in
  `TRUSTED_PROXIES`.

## Consequences

- The IP limiter is per instance. With several replicas the effective limit is multiplied by the
  replica count; a shared limit belongs on the ingress or gateway.
- An attacker who knows an email can lock that account for `LOCKOUT_DURATION`. The IP limiter and
  the short lockout window keep this cheap to live with; the audit log records every locked attempt.
