package service

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// AuditService implements port.AuditService by persisting events through an AuditLogRepository.
type AuditService struct {
	repo   port.AuditLogRepository
	logger *logger.Logger
	now    func() time.Time
}

// NewAuditService returns an AuditService writing to repo.
func NewAuditService(repo port.AuditLogRepository, log *logger.Logger) (*AuditService, error) {
	if repo == nil {
		return nil, errors.New("audit service: repository is required")
	}
	return &AuditService{
		repo:   repo,
		logger: componentLogger(log, "audit"),
		now:    time.Now,
	}, nil
}

// Record stores e as an audit entry, joining the transaction carried in ctx when there is one.
// Empty client metadata is stored as NULL.
func (s *AuditService) Record(ctx context.Context, e domain.AuditEvent) error {
	if e.Action == "" {
		return apperror.Internal("audit event has no action", nil)
	}
	entry := &domain.AuditLog{
		ActorID:      e.ActorID,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		IPAddress:    optionalString(e.IP),
		UserAgent:    optionalString(e.UserAgent),
		CreatedAt:    s.now(),
	}
	if len(e.Details) > 0 {
		details, err := json.Marshal(e.Details)
		if err != nil {
			return apperror.Internal("failed to encode audit details", err)
		}
		entry.Details = details
	}
	if err := s.repo.Create(ctx, entry); err != nil {
		s.logger.FromContext(ctx).Error("failed to store audit entry", "action", e.Action, "error", err)
		return asInternal("failed to store audit entry", err)
	}
	return nil
}

// ListByActor returns up to limit of the most recent entries recorded for actions of actorID.
func (s *AuditService) ListByActor(ctx context.Context, actorID int64, limit int) ([]domain.AuditLog, error) {
	entries, err := s.repo.ListByUser(ctx, actorID, limit)
	if err != nil {
		return nil, asInternal("failed to list audit entries", err)
	}
	return entries, nil
}

// optionalString returns nil for an empty string and a pointer to v otherwise.
func optionalString(v string) *string {
	if v == "" {
		return nil
	}
	return &v
}
