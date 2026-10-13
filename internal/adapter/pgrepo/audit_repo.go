package pgrepo

import (
	"context"
	"fmt"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// AuditLogRepository implements port.AuditLogRepository on PostgreSQL.
type AuditLogRepository struct {
	repo
}

// NewAuditLogRepository returns an AuditLogRepository backed by db.
func NewAuditLogRepository(db *gorm.DB) *AuditLogRepository {
	return &AuditLogRepository{repo: repo{db: db}}
}

// Create inserts entry, joining the transaction carried in ctx when there is one.
// Empty Details and IPAddress values are stored as NULL.
func (r *AuditLogRepository) Create(ctx context.Context, entry *domain.AuditLog) error {
	if len(entry.Details) == 0 {
		entry.Details = nil
	}
	if entry.IPAddress != nil && *entry.IPAddress == "" {
		entry.IPAddress = nil
	}
	if err := r.conn(ctx).Create(entry).Error; err != nil {
		return apperror.Internal("failed to create audit log", err)
	}
	return nil
}

// ListByUser returns up to limit entries whose actor is userID, newest first. limit must be
// positive: the handler clamps it, so any other value is a programming error and yields
// apperror.Internal rather than a substituted default.
func (r *AuditLogRepository) ListByUser(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error) {
	if limit < 1 {
		return nil, apperror.Internal("failed to list audit logs", fmt.Errorf("invalid limit %d: must be positive", limit))
	}
	entries := []domain.AuditLog{}
	err := r.conn(ctx).
		Where("actor_id = ?", userID).
		Order("created_at DESC, id DESC").
		Limit(limit).
		Find(&entries).Error
	if err != nil {
		return nil, apperror.Internal("failed to list audit logs", err)
	}
	return entries, nil
}
