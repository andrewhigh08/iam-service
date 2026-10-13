// Package postgres provides PostgreSQL-based repository implementations with circuit breaker protection.
package postgres

import (
	"context"
	"time"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/circuitbreaker"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// CircuitBreakerConfig holds configuration for repository circuit breakers.
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit.
	MaxFailures int

	// Timeout is the duration to wait before testing if service recovered.
	Timeout time.Duration

	// OnStateChange is called when circuit breaker state changes.
	OnStateChange func(name string, from, to circuitbreaker.State)
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration for PostgreSQL.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures: 3,
		Timeout:     30 * time.Second,
	}
}

// ==================== User Repository with Circuit Breaker ====================

// UserRepositoryWithCB wraps UserRepository with circuit breaker protection.
type UserRepositoryWithCB struct {
	repo    *UserRepository
	cbRead  *circuitbreaker.CircuitBreaker
	cbWrite *circuitbreaker.CircuitBreaker
}

// NewUserRepositoryWithCB creates a new UserRepository with circuit breaker.
func NewUserRepositoryWithCB(repo *UserRepository, config CircuitBreakerConfig) *UserRepositoryWithCB {
	cbReadConfig := circuitbreaker.Config{
		Name:                "postgres-user-read",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	cbWriteConfig := circuitbreaker.Config{
		Name:                "postgres-user-write",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &UserRepositoryWithCB{
		repo:    repo,
		cbRead:  circuitbreaker.New(cbReadConfig),
		cbWrite: circuitbreaker.New(cbWriteConfig),
	}
}

// Create creates a new user with circuit breaker protection.
func (r *UserRepositoryWithCB) Create(ctx context.Context, user *domain.User) error {
	return r.cbWrite.Execute(ctx, func(ctx context.Context) error {
		return r.repo.Create(ctx, user)
	})
}

// CreateTx creates a new user within a transaction.
// Note: Transaction operations are not circuit-breaker protected individually.
// since they are part of a larger transaction that should be managed as a unit.
func (r *UserRepositoryWithCB) CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	return r.repo.CreateTx(ctx, tx, user)
}

// FindByID retrieves a user by ID with circuit breaker protection.
func (r *UserRepositoryWithCB) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	return circuitbreaker.ExecuteWithResult(ctx, r.cbRead, func(ctx context.Context) (*domain.User, error) {
		return r.repo.FindByID(ctx, id)
	})
}

// FindByEmail retrieves a user by email with circuit breaker protection.
func (r *UserRepositoryWithCB) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return circuitbreaker.ExecuteWithResult(ctx, r.cbRead, func(ctx context.Context) (*domain.User, error) {
		return r.repo.FindByEmail(ctx, email)
	})
}

// Update updates a user with circuit breaker protection.
func (r *UserRepositoryWithCB) Update(ctx context.Context, user *domain.User) error {
	return r.cbWrite.Execute(ctx, func(ctx context.Context) error {
		return r.repo.Update(ctx, user)
	})
}

// UpdateTx updates a user within a transaction.
func (r *UserRepositoryWithCB) UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	return r.repo.UpdateTx(ctx, tx, user)
}

// Delete soft-deletes a user with circuit breaker protection.
func (r *UserRepositoryWithCB) Delete(ctx context.Context, id int64) error {
	return r.cbWrite.Execute(ctx, func(ctx context.Context) error {
		return r.repo.Delete(ctx, id)
	})
}

// DeleteTx soft-deletes a user within a transaction.
func (r *UserRepositoryWithCB) DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error {
	return r.repo.DeleteTx(ctx, tx, id)
}

// List retrieves users with filtering and circuit breaker protection.
func (r *UserRepositoryWithCB) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int64, error) {
	type result struct {
		users []domain.User
		total int64
	}

	res, err := circuitbreaker.ExecuteWithResult(ctx, r.cbRead, func(ctx context.Context) (result, error) {
		users, total, err := r.repo.List(ctx, filter)
		return result{users: users, total: total}, err
	})

	if err != nil {
		return nil, 0, err
	}

	return res.users, res.total, nil
}

// ExistsByEmail checks email existence with circuit breaker protection.
func (r *UserRepositoryWithCB) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	return circuitbreaker.ExecuteWithResult(ctx, r.cbRead, func(ctx context.Context) (bool, error) {
		return r.repo.ExistsByEmail(ctx, email)
	})
}

// HardDelete permanently deletes a user (for compensating transactions).
func (r *UserRepositoryWithCB) HardDelete(ctx context.Context, id int64) error {
	return r.cbWrite.Execute(ctx, func(ctx context.Context) error {
		return r.repo.HardDelete(ctx, id)
	})
}

// ReadCircuitBreakerState returns the current state of the read circuit breaker.
func (r *UserRepositoryWithCB) ReadCircuitBreakerState() circuitbreaker.State {
	return r.cbRead.State()
}

// WriteCircuitBreakerState returns the current state of the write circuit breaker.
func (r *UserRepositoryWithCB) WriteCircuitBreakerState() circuitbreaker.State {
	return r.cbWrite.State()
}

// Ensure interface compliance.
var _ port.UserRepository = (*UserRepositoryWithCB)(nil)

// ==================== Audit Log Repository with Circuit Breaker ====================

// AuditLogRepositoryWithCB wraps AuditLogRepository with circuit breaker protection.
type AuditLogRepositoryWithCB struct {
	repo *AuditLogRepository
	cb   *circuitbreaker.CircuitBreaker
}

// NewAuditLogRepositoryWithCB creates a new AuditLogRepository with circuit breaker.
func NewAuditLogRepositoryWithCB(repo *AuditLogRepository, config CircuitBreakerConfig) *AuditLogRepositoryWithCB {
	// Audit logs have more lenient settings since they're not critical path.
	cbConfig := circuitbreaker.Config{
		Name:                "postgres-audit",
		MaxFailures:         config.MaxFailures * 2, // More tolerant.
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &AuditLogRepositoryWithCB{
		repo: repo,
		cb:   circuitbreaker.New(cbConfig),
	}
}

// Create creates a new audit log entry with circuit breaker protection.
func (r *AuditLogRepositoryWithCB) Create(ctx context.Context, log *domain.AuditLog) error {
	return r.cb.Execute(ctx, func(ctx context.Context) error {
		return r.repo.Create(ctx, log)
	})
}

// CreateTx creates a new audit log entry within a transaction.
func (r *AuditLogRepositoryWithCB) CreateTx(ctx context.Context, tx *gorm.DB, log *domain.AuditLog) error {
	return r.repo.CreateTx(ctx, tx, log)
}

// FindByUserID retrieves audit logs for a user with circuit breaker protection.
func (r *AuditLogRepositoryWithCB) FindByUserID(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error) {
	return circuitbreaker.ExecuteWithResult(ctx, r.cb, func(ctx context.Context) ([]domain.AuditLog, error) {
		return r.repo.FindByUserID(ctx, userID, limit)
	})
}

// FindByResourceID retrieves audit logs for a resource with circuit breaker protection.
func (r *AuditLogRepositoryWithCB) FindByResourceID(ctx context.Context, resourceType, resourceID string, limit int) ([]domain.AuditLog, error) {
	return circuitbreaker.ExecuteWithResult(ctx, r.cb, func(ctx context.Context) ([]domain.AuditLog, error) {
		return r.repo.FindByResourceID(ctx, resourceType, resourceID, limit)
	})
}

// CircuitBreakerState returns the current state of the circuit breaker.
func (r *AuditLogRepositoryWithCB) CircuitBreakerState() circuitbreaker.State {
	return r.cb.State()
}

// Ensure interface compliance.
var _ port.AuditLogRepository = (*AuditLogRepositoryWithCB)(nil)

// ==================== Transaction Manager with Circuit Breaker ====================

// TransactionManagerWithCB wraps TransactionManager with circuit breaker protection.
type TransactionManagerWithCB struct {
	tm *TransactionManager
	cb *circuitbreaker.CircuitBreaker
}

// NewTransactionManagerWithCB creates a new TransactionManager with circuit breaker.
func NewTransactionManagerWithCB(tm *TransactionManager, config CircuitBreakerConfig) *TransactionManagerWithCB {
	cbConfig := circuitbreaker.Config{
		Name:                "postgres-transaction",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &TransactionManagerWithCB{
		tm: tm,
		cb: circuitbreaker.New(cbConfig),
	}
}

// Begin starts a new transaction with circuit breaker protection.
func (t *TransactionManagerWithCB) Begin(ctx context.Context) (*gorm.DB, error) {
	return circuitbreaker.ExecuteWithResult(ctx, t.cb, func(ctx context.Context) (*gorm.DB, error) {
		return t.tm.Begin(ctx)
	})
}

// Commit commits a transaction.
func (t *TransactionManagerWithCB) Commit(tx *gorm.DB) error {
	// Commit is not circuit-breaker protected because it's part of an already-started transaction.
	return t.tm.Commit(tx)
}

// Rollback rolls back a transaction.
func (t *TransactionManagerWithCB) Rollback(tx *gorm.DB) error {
	// Rollback is not circuit-breaker protected.
	return t.tm.Rollback(tx)
}

// WithTransaction executes a function within a transaction with circuit breaker protection.
func (t *TransactionManagerWithCB) WithTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	return t.cb.Execute(ctx, func(ctx context.Context) error {
		return t.tm.WithTransaction(ctx, fn)
	})
}

// CircuitBreakerState returns the current state of the circuit breaker.
func (t *TransactionManagerWithCB) CircuitBreakerState() circuitbreaker.State {
	return t.cb.State()
}

// Ensure interface compliance.
var _ port.Transaction = (*TransactionManagerWithCB)(nil)
