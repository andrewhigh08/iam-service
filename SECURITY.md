# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Send a description of the issue, the
affected endpoint or component and, if possible, steps to reproduce to the maintainer through the
contact listed on the GitHub profile (https://github.com/andrewhigh08). You will get an
acknowledgement within a few days.

## Scope

The service is an IAM backend. The security model is described in [docs/adr](docs/adr) and in
the security section of the README. Reports about the following are especially welcome:

- token validation, revocation and session handling;
- authorization bypass (RBAC);
- account enumeration, lockout or rate-limit bypass;
- leakage of secrets in logs, responses or the container image.

## Supported versions

Only the `main` branch and the latest tag are supported.
