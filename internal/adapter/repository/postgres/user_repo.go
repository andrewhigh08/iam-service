// Package postgres provides PostgreSQL-based repository implementations.
//
// This package implements all repository interfaces defined in port package
// using GORM as the ORM layer.
package postgres

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// UserRepository implements port.UserRepository using PostgreSQL.
//
// Provides CRUD operations for user entities with support for
// soft delete and transactional operations.
type UserRepository struct {
	db *gorm.DB // Database connection
}

// NewUserRepository creates a new UserRepository instance.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user in the database.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	return r.CreateTx(ctx, r.db, user)
}

// CreateTx creates a new user within an existing transaction.
// Use this when creating a user as part of a larger transactional operation.
func (r *UserRepository) CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	if err := tx.WithContext(ctx).Create(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || isDuplicateKeyError(err) {
			return apperror.Conflict("user", "email", user.Email)
		}
		return apperror.Internal("failed to create user", err)
	}
	return nil
}

// FindByID retrieves a user by their unique identifier.
// Excludes soft-deleted users.
func (r *UserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NotFound("user", id)
		}
		return nil, apperror.Internal("failed to find user", err)
	}
	return &user, nil
}

// FindByEmail retrieves a user by their email address.
// Excludes soft-deleted users.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Where("email = ? AND deleted_at IS NULL", email).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NotFound("user", email)
		}
		return nil, apperror.Internal("failed to find user", err)
	}
	return &user, nil
}

// Update updates an existing user in the database.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	return r.UpdateTx(ctx, r.db, user)
}

// UpdateTx updates an existing user within an existing transaction.
func (r *UserRepository) UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	result := tx.WithContext(ctx).Save(user)
	if result.Error != nil {
		return apperror.Internal("failed to update user", result.Error)
	}
	if result.RowsAffected == 0 {
		return apperror.NotFound("user", user.ID)
	}
	return nil
}

// Delete performs a soft-delete on a user.
// The user record is not physically removed from the database.
func (r *UserRepository) Delete(ctx context.Context, id int64) error {
	return r.DeleteTx(ctx, r.db, id)
}

// DeleteTx performs a soft-delete within an existing transaction.
func (r *UserRepository) DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error {
	result := tx.WithContext(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		Delete(&domain.User{})

	if result.Error != nil {
		return apperror.Internal("failed to delete user", result.Error)
	}
	if result.RowsAffected == 0 {
		return apperror.NotFound("user", id)
	}
	return nil
}

// HardDelete permanently removes a user from the database.
// Used for compensating transactions in saga pattern.
func (r *UserRepository) HardDelete(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Unscoped().Delete(&domain.User{}, id)
	if result.Error != nil {
		return apperror.Internal("failed to hard delete user", result.Error)
	}
	return nil
}

// List retrieves users with filtering and pagination.
// Returns: users slice, total count, error.
func (r *UserRepository) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int64, error) {
	var users []domain.User
	var total int64

	query := r.db.WithContext(ctx).Model(&domain.User{}).Where("deleted_at IS NULL")

	// Apply status filter
	switch filter.Status {
	case "active":
		query = query.Where("is_blocked = ?", false)
	case "blocked":
		query = query.Where("is_blocked = ?", true)
	}

	// Apply search filter (email or full name)
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		query = query.Where("email ILIKE ? OR full_name ILIKE ?", search, search)
	}

	// Count total matching records
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, apperror.Internal("failed to count users", err)
	}

	// Calculate offset for pagination
	offset := (filter.Page - 1) * filter.PageSize
	if offset < 0 {
		offset = 0
	}

	// Get paginated results
	err := query.
		Order("created_at DESC").
		Limit(filter.PageSize).
		Offset(offset).
		Find(&users).Error

	if err != nil {
		return nil, 0, apperror.Internal("failed to list users", err)
	}

	return users, total, nil
}

// ExistsByEmail checks if a user with the given email already exists.
// Excludes soft-deleted users.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("email = ? AND deleted_at IS NULL", email).
		Count(&count).Error

	if err != nil {
		return false, apperror.Internal("failed to check email existence", err)
	}
	return count > 0, nil
}

// isDuplicateKeyError checks if the error is a PostgreSQL duplicate key violation.
// PostgreSQL error code 23505 indicates unique_violation.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	errMsg := err.Error()
	return errMsg != "" && (strings.Contains(errMsg, "duplicate key") || strings.Contains(errMsg, "23505"))
}
