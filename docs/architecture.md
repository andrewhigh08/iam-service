# IAM Service Architecture

## Overview

IAM Service is an Identity and Access Management microservice built with Go, following Clean Architecture principles (Hexagonal/Ports & Adapters pattern).

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              External Clients                               │
│                        (Web Apps, Mobile Apps, APIs)                        │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                            HTTP Layer (Gin)                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │  Middleware │  │  Middleware │  │  Middleware │  │  Middleware │         │
│  │   Auth/JWT  │  │   RBAC      │  │  RateLimit  │  │   Metrics   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
│                                                                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐         │
│  │   Handler   │  │   Handler   │  │   Handler   │  │   Handler   │         │
│  │    Auth     │  │    User     │  │   Health    │  │   Swagger   │         │
│  └─────────────┘  └─────────────┘  └─────────────┘  └─────────────┘         │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                           Service Layer (Business Logic)                    │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐              │
│  │   AuthService   │  │   UserService   │  │  AuditService   │              │
│  │                 │  │                 │  │                 │              │
│  │  - Login        │  │  - CreateUser   │  │  - LogAction    │              │
│  │  - ValidateJWT  │  │  - BlockUser    │  │  - GetLogs      │              │
│  │  - ChangePass   │  │  - ListUsers    │  │                 │              │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘              │
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────┐            │
│  │                   AuthorizationService (Casbin RBAC)        │            │
│  │   - CheckAccess(userID, resource, action) -> bool           │            │
│  │   - 3-level caching: Local -> Redis -> Database             │            │
│  └─────────────────────────────────────────────────────────────┘            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                    ┌─────────────────┼─────────────────┐
                    ▼                 ▼                 ▼
┌───────────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│   PostgreSQL Adapter  │ │    Redis Adapter  │ │   Casbin Adapter  │
│                       │ │                   │ │                   │
│  - UserRepository     │ │  - TokenCache     │ │  - PolicyStore    │
│  - AuditRepository    │ │  - RateLimitCache │ │  - RoleCache      │
│  - TransactionManager │ │  - AuthzCache     │ │                   │
└───────────────────────┘ └───────────────────┘ └───────────────────┘
          │                       │                       │
          ▼                       ▼                       ▼
┌───────────────────────┐ ┌───────────────────┐ ┌───────────────────┐
│      PostgreSQL       │ │       Redis       │ │   Casbin Model    │
│                       │ │                   │ │                   │
│  - users              │ │  - JWT blacklist  │ │  - RBAC policies  │
│  - audit_logs         │ │  - Rate limits    │ │  - Role mappings  │
│  - casbin_rule        │ │  - Authz cache    │ │                   │
└───────────────────────┘ └───────────────────┘ └───────────────────┘
```

## Directory Structure

```
iam-service/
├── cmd/
│   └── api/
│       └── main.go              # Application entrypoint, DI setup
├── internal/
│   ├── adapter/                 # Infrastructure layer (adapters)
│   │   ├── cache/redis/         # Redis cache implementation
│   │   ├── http/
│   │   │   ├── handler/         # HTTP request handlers
│   │   │   ├── middleware/      # HTTP middleware (auth, rate limit, etc.)
│   │   │   └── response/        # Unified API response format
│   │   └── repository/postgres/ # PostgreSQL repositories
│   ├── config/                  # Configuration management
│   ├── domain/                  # Domain models (entities)
│   ├── pkg/                     # Shared utilities
│   │   ├── apperror/            # Application error types
│   │   ├── logger/              # Structured logging (slog)
│   │   ├── telemetry/           # OpenTelemetry tracing
│   │   └── validator/           # Custom validation rules
│   ├── port/                    # Interfaces (ports)
│   │   ├── repository.go        # Repository interfaces
│   │   ├── service.go           # Service interfaces
│   │   └── cache.go             # Cache interfaces
│   └── service/                 # Business logic layer
├── test/
│   ├── fixtures/                # Test data factories
│   ├── integration/             # Integration tests (testcontainers)
│   └── mocks/                   # Generated mocks
├── docs/                        # Swagger documentation
└── configs/                     # Configuration files
```

## Request Flow

```
┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client  │────▶│Middleware│────▶│ Handler  │────▶│ Service  │────▶│Repository│
└──────────┘     └──────────┘     └──────────┘     └──────────┘     └──────────┘
                      │                                                  │
                      │           ┌──────────┐                           │
                      └──────────▶│  Cache   │◀──────────────────────────┘
                                  └──────────┘
```

### Authentication Flow

```
┌────────┐                    ┌─────────┐                    ┌──────────┐
│ Client │                    │   IAM   │                    │ Database │
└────┬───┘                    └────┬────┘                    └────┬─────┘
     │                             │                              │
     │  POST /auth/login           │                              │
     │  {email, password}          │                              │
     │────────────────────────────▶│                              │
     │                             │                              │
     │                             │  FindByEmail(email)          │
     │                             │─────────────────────────────▶│
     │                             │                              │
     │                             │  User{id, password_hash}     │
     │                             │◀─────────────────────────────│
     │                             │                              │
     │                             │  bcrypt.Compare()            │
     │                             │  ──────────────────          │
     │                             │                              │
     │                             │  GenerateJWT(claims)         │
     │                             │  ──────────────────          │
     │                             │                              │
     │  {access_token, user}       │                              │
     │◀────────────────────────────│                              │
     │                             │                              │
```

### Authorization Flow (RBAC)

```
┌────────┐          ┌─────────────┐          ┌───────┐          ┌────────┐
│ Client │          │  Middleware │          │ Cache │          │ Casbin │
└────┬───┘          └──────┬──────┘          └───┬───┘          └────┬───┘
     │                     │                     │                   │
     │  GET /api/v1/users  │                     │                   │
     │  Authorization: JWT │                     │                   │
     │────────────────────▶│                     │                   │
     │                     │                     │                   │
     │                     │  CheckCache(key)    │                   │
     │                     │────────────────────▶│                   │
     │                     │                     │                   │
     │                     │  MISS               │                   │
     │                     │◀────────────────────│                   │
     │                     │                     │                   │
     │                     │  Enforce(sub,obj,act)                   │
     │                     │────────────────────────────────────────▶│
     │                     │                     │                   │
     │                     │  allowed: true      │                   │
     │                     │◀────────────────────────────────────────│
     │                     │                     │                   │
     │                     │  SetCache(key, true, TTL)               │
     │                     │────────────────────▶│                   │
     │                     │                     │                   │
     │  200 OK             │                     │                   │
     │◀────────────────────│                     │                   │
```

## Key Components

### Domain Layer (`internal/domain/`)

Pure domain models without external dependencies:

- `User` - User entity with authentication data
- `AuditLog` - Audit trail entry
- `ChangePasswordRequest`, `CreateUserRequest` - Request DTOs

### Port Layer (`internal/port/`)

Interfaces defining contracts:

```go
type UserRepository interface {
    Create(ctx context.Context, user *domain.User) error
    FindByID(ctx context.Context, id int64) (*domain.User, error)
    FindByEmail(ctx context.Context, email string) (*domain.User, error)
    Update(ctx context.Context, user *domain.User) error
    Delete(ctx context.Context, id int64) error
    List(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)
}

type AuthorizationService interface {
    CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error)
    AddRoleToUser(ctx context.Context, userID int64, role string) error
    GetUserRoles(ctx context.Context, userID int64) ([]string, error)
}
```

### Service Layer (`internal/service/`)

Business logic with transaction management:

- **AuthService** - Authentication, JWT tokens, password management
- **UserService** - User CRUD with saga pattern for distributed transactions
- **AuditService** - Audit logging with transactional support
- **AuthorizationService** - Casbin RBAC with 3-level caching

### Adapter Layer (`internal/adapter/`)

Infrastructure implementations:

- **PostgreSQL** - User and audit repositories with GORM
- **Redis** - Caching for tokens, rate limits, authorization decisions
- **HTTP** - Gin handlers with middleware chain

## Security Features

### Authentication
- JWT RS256 tokens with RSA key pairs
- One-time password (OTP) support for first login
- Password complexity validation

### Authorization
- Casbin RBAC with role hierarchy
- Resource-action based permissions
- 3-level caching (local → Redis → database)

### Rate Limiting
- Global: 100 req/sec per IP
- Login: 5 attempts/min per IP

### Security Headers
```
X-Content-Type-Options: nosniff
X-XSS-Protection: 1; mode=block
X-Frame-Options: DENY
Content-Security-Policy: default-src 'none'
X-Request-ID: <uuid>
```

## Observability

### Metrics (Prometheus)
```
iam_http_requests_total{method, path, status}
iam_http_request_duration_seconds{method, path}
```

### Tracing (OpenTelemetry)
- Distributed tracing with context propagation
- Span attributes for user ID, request ID

### Logging (slog)
- Structured JSON logging
- Request ID correlation
- User ID context

### Health Checks
- `/health/live` - Liveness probe
- `/health/ready` - Readiness probe (DB + Redis)

## Data Flow Patterns

### Saga Pattern for User Creation

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Create     │     │  Assign     │     │  Success    │
│  User (DB)  │────▶│  Role       │────▶│  Response   │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           │ On Failure
                           ▼
                    ┌─────────────┐
                    │ Compensate: │
                    │ Hard Delete │
                    │    User     │
                    └─────────────┘
```

### Cache-Aside Pattern

```
┌────────┐          ┌───────┐          ┌──────────┐
│Service │          │ Cache │          │ Database │
└────┬───┘          └───┬───┘          └────┬─────┘
     │                  │                   │
     │  Get(key)        │                   │
     │─────────────────▶│                   │
     │                  │                   │
     │  MISS            │                   │
     │◀─────────────────│                   │
     │                  │                   │
     │  Query(id)       │                   │
     │─────────────────────────────────────▶│
     │                  │                   │
     │  Data            │                   │
     │◀─────────────────────────────────────│
     │                  │                   │
     │  Set(key, data)  │                   │
     │─────────────────▶│                   │
     │                  │                   │
```

## Configuration

Environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | HTTP server port | 8080 |
| `DB_HOST` | PostgreSQL host | localhost |
| `DB_PORT` | PostgreSQL port | 5432 |
| `DB_NAME` | Database name | iam_db |
| `DB_USER` | Database user | iam_user |
| `DB_PASSWORD` | Database password | - |
| `REDIS_HOST` | Redis host | localhost |
| `REDIS_PORT` | Redis port | 6379 |
| `JWT_PRIVATE_KEY_PATH` | RSA private key path | - |
| `JWT_PUBLIC_KEY_PATH` | RSA public key path | - |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | OTLP exporter endpoint | - |

## API Endpoints

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| POST | `/auth/login` | User login | No |
| POST | `/auth/first-time-password-change` | Change OTP | No |
| POST | `/api/v1/change-password` | Change password | Yes |
| GET | `/api/v1/users` | List users | Yes + RBAC |
| POST | `/api/v1/users` | Create user | Yes + RBAC |
| GET | `/api/v1/users/:id` | Get user | Yes + RBAC |
| POST | `/api/v1/users/:id/block` | Block user | Yes + RBAC |
| POST | `/api/v1/users/:id/unblock` | Unblock user | Yes + RBAC |
| GET | `/health` | Basic health check | No |
| GET | `/health/live` | Liveness probe | No |
| GET | `/health/ready` | Readiness probe | No |
| GET | `/metrics` | Prometheus metrics | No |
| GET | `/swagger/*` | Swagger UI | No |
