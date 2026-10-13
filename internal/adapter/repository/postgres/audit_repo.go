// Package postgres provides PostgreSQL-based repository implementations.
package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// AuditLogRepository implements port.AuditLogRepository using PostgreSQL.
//
// Stores audit log entries for security, compliance, and debugging purposes.
type AuditLogRepository struct {
	db *gorm.DB // Database connection
}

// NewAuditLogRepository creates a new AuditLogRepository instance.
func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{db: db}
}

// Create creates a new audit log entry in the database.
func (r *AuditLogRepository) Create(ctx context.Context, log *domain.AuditLog) error {
	return r.CreateTx(ctx, r.db, log)
}

// CreateTx creates a new audit log entry within an existing transaction.
// Use this when logging must be part of a larger atomic operation.
func (r *AuditLogRepository) CreateTx(ctx context.Context, tx *gorm.DB, log *domain.AuditLog) error {
	if err := tx.WithContext(ctx).Create(log).Error; err != nil {
		return apperror.Internal("failed to create audit log", err)
	}
	return nil
}

// FindByUserID retrieves audit logs for a specific user.
// Results are ordered by creation time (newest first) and limited.
func (r *AuditLogRepository) FindByUserID(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog

	err := r.db.WithContext(ctx).
		Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error

	if err != nil {
		return nil, apperror.Internal("failed to find audit logs by user", err)
	}
	return logs, nil
}

// FindByResourceID retrieves audit logs for a specific resource.
// Useful for tracking all actions performed on a particular entity.
func (r *AuditLogRepository) FindByResourceID(ctx context.Context, resourceType, resourceID string, limit int) ([]domain.AuditLog, error) {
	var logs []domain.AuditLog

	err := r.db.WithContext(ctx).
		Where("resource_type = ? AND resource_id = ?", resourceType, resourceID).
		Order("created_at DESC").
		Limit(limit).
		Find(&logs).Error

	if err != nil {
		return nil, apperror.Internal("failed to find audit logs by resource", err)
	}
	return logs, nil
}
