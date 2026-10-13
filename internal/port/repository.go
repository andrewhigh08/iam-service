// Package port defines the interfaces the service layer depends on.
//
// Adapters under internal/adapter implement them. Nothing in this package may import
// gorm, gin or redis types.
package port

import (
	"context"
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// UserFilter narrows and paginates a user listing.
// Status is one of "", "all", "active" or "blocked"; Page is 1-based.
type UserFilter struct {
	Status   string
	Search   string
	Page     int
	PageSize int
}

// UserRepository persists users. Writes are intent-specific and touch only the columns of
// that intent, so concurrent changes to other columns are never overwritten.
type UserRepository interface {
	// Create inserts a new user. Returns apperror.Conflict when the email is already taken.
	Create(ctx context.Context, user *domain.User) error
	// FindByID returns the user with the given id or apperror.NotFound.
	FindByID(ctx context.Context, id int64) (*domain.User, error)
	// FindByEmail returns the user with the given email or apperror.NotFound.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	// UpdatePassword replaces the password hash of the user id, records whether it is temporary
	// and when it was changed. Returns apperror.NotFound when no row matched.
	UpdatePassword(ctx context.Context, id int64, hash string, temporary bool, changedAt time.Time) error
	// SetBlocked sets the blocked flag of the user id. Returns apperror.NotFound when no row matched.
	SetBlocked(ctx context.Context, id int64, blocked bool) error
	// HardDelete physically removes a user; used only to compensate a failed creation.
	HardDelete(ctx context.Context, id int64) error
	// List returns one page of users matching f together with the total match count.
	List(ctx context.Context, f UserFilter) ([]domain.User, int64, error)
	// ExistsByEmail reports whether a user with the given email exists.
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// AuditLogRepository persists audit log entries.
type AuditLogRepository interface {
	// Create inserts an audit log entry.
	Create(ctx context.Context, entry *domain.AuditLog) error
	// ListByUser returns the most recent entries whose actor is userID, newest first.
	ListByUser(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error)
}
