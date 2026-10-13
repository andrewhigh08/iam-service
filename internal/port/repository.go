// Package port defines interfaces (ports) for the application's external dependencies.
//
// This package follows the Hexagonal Architecture (Ports and Adapters) pattern,
// where ports define the contracts that adapters must implement.
package port

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// UserFilter defines filtering options for user queries.
//
// Fields:
//   - Status: Filter by user status ("active", "blocked", "all")
//   - Search: Search string for email or full name
//   - Page: Page number for pagination (1-based)
//   - PageSize: Number of items per page
type UserFilter struct {
	Status   string // "active", "blocked", "all" / "active", "blocked", "all"
	Search   string // Search by email or full name
	Page     int    // Page number
	PageSize int    // Items per page
}

// UserRepository defines the interface for user data access operations.
//
// This interface abstracts the data storage layer, allowing different
// implementations (PostgreSQL, MySQL, etc.) to be used interchangeably.
type UserRepository interface {
	// Create creates a new user in the database.
	Create(ctx context.Context, user *domain.User) error

	// CreateTx creates a new user within an existing database transaction.
	CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error

	// FindByID retrieves a user by their unique identifier.
	// Returns nil if user is not found.
	FindByID(ctx context.Context, id int64) (*domain.User, error)

	// FindByEmail retrieves a user by their email address.
	// Returns nil if user is not found.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// Update updates an existing user's information.
	Update(ctx context.Context, user *domain.User) error

	// UpdateTx updates an existing user within a transaction.
	UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error

	// Delete performs a soft delete on a user (sets deleted_at timestamp).
	Delete(ctx context.Context, id int64) error

	// DeleteTx performs a soft delete within a transaction.
	DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error

	// List retrieves users with filtering and pagination support.
	// Returns the list of users, total count, and any error.
	List(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)

	// ExistsByEmail checks if a user with the given email already exists.
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// AuditLogRepository defines the interface for audit log data access.
//
// Audit logs track all significant actions in the system for compliance
// and security purposes.
type AuditLogRepository interface {
	// Create creates a new audit log entry.
	Create(ctx context.Context, log *domain.AuditLog) error

	// CreateTx creates a new audit log entry within a transaction.
	CreateTx(ctx context.Context, tx *gorm.DB, log *domain.AuditLog) error

	// FindByUserID retrieves recent audit logs for a specific user.
	FindByUserID(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error)

	// FindByResourceID retrieves audit logs for a specific resource.
	FindByResourceID(ctx context.Context, resourceType string, resourceID string, limit int) ([]domain.AuditLog, error)
}

// Transaction provides database transaction support.
//
// Transactions ensure data consistency when multiple operations
// need to be performed atomically.
type Transaction interface {
	// Begin starts a new database transaction.
	Begin(ctx context.Context) (*gorm.DB, error)

	// Commit commits a transaction, making all changes permanent.
	Commit(tx *gorm.DB) error

	// Rollback rolls back a transaction, discarding all changes.
	Rollback(tx *gorm.DB) error

	// WithTransaction executes a function within a transaction.
	// Automatically commits on success or rolls back on error.
	WithTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error
}
