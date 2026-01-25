// Package service contains the business logic layer of the application.
// Пакет service содержит слой бизнес-логики приложения.
package service

import (
	"context"
	"encoding/json"
	"time"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/adapter/repository/postgres"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// AuditService implements port.AuditService interface.
// AuditService реализует интерфейс port.AuditService.
//
// Provides audit logging for tracking user actions for security,
// compliance, and debugging purposes.
// Предоставляет аудит-логирование для отслеживания действий пользователей
// в целях безопасности, соответствия требованиям и отладки.
type AuditService struct {
	auditRepo port.AuditLogRepository // Audit log repository / Репозиторий аудит-лога
	logger    *logger.Logger          // Logger instance / Экземпляр логгера
}

// NewAuditService creates a new AuditService instance.
// NewAuditService создаёт новый экземпляр AuditService.
func NewAuditService(auditRepo port.AuditLogRepository, log *logger.Logger) *AuditService {
	return &AuditService{
		auditRepo: auditRepo,
		logger:    log.WithComponent("audit_service"),
	}
}

// LogAction logs an action to the audit trail.
// LogAction записывает действие в аудит-лог.
func (s *AuditService) LogAction(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error {
	return s.LogActionWithContext(ctx, userID, action, resourceType, resourceID, details, "", "")
}

// LogActionTx logs an action within an existing transaction.
// LogActionTx записывает действие в рамках существующей транзакции.
func (s *AuditService) LogActionTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error {
	return s.LogActionWithContextTx(ctx, tx, userID, action, resourceType, resourceID, details, "", "")
}

// LogActionWithContext logs an action with IP address and user agent.
// LogActionWithContext записывает действие с IP-адресом и user agent.
func (s *AuditService) LogActionWithContext(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error {
	log := s.logger.WithContext(ctx)

	// Serialize details to JSON / Сериализуем детали в JSON
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Error("failed to marshal audit details", "error", err)
		return apperror.Internal("failed to marshal audit details", err)
	}

	// Prepare optional fields / Подготавливаем опциональные поля
	var ipPtr, uaPtr *string
	if ipAddress != "" {
		ipPtr = &ipAddress
	}
	if userAgent != "" {
		uaPtr = &userAgent
	}

	// Create audit log entry / Создаём запись аудит-лога
	auditLog := &domain.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
		IPAddress:    ipPtr,
		UserAgent:    uaPtr,
		CreatedAt:    time.Now(),
	}

	if err := s.auditRepo.Create(ctx, auditLog); err != nil {
		log.Error("failed to create audit log", "action", action, "error", err)
		return err
	}

	log.Debug("audit log created", "action", action, "resource_type", resourceType, "resource_id", resourceID)
	return nil
}

// LogActionWithContextTx logs an action with context within a transaction.
// LogActionWithContextTx записывает действие с контекстом в рамках транзакции.
// Use this when audit log must be part of a larger atomic operation.
// Используйте, когда аудит-лог должен быть частью большой атомарной операции.
func (s *AuditService) LogActionWithContextTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error {
	log := s.logger.WithContext(ctx)

	// Serialize details to JSON / Сериализуем детали в JSON
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		log.Error("failed to marshal audit details", "error", err)
		return apperror.Internal("failed to marshal audit details", err)
	}

	// Prepare optional fields / Подготавливаем опциональные поля
	var ipPtr, uaPtr *string
	if ipAddress != "" {
		ipPtr = &ipAddress
	}
	if userAgent != "" {
		uaPtr = &userAgent
	}

	// Create audit log entry / Создаём запись аудит-лога
	auditLog := &domain.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		Details:      detailsJSON,
		IPAddress:    ipPtr,
		UserAgent:    uaPtr,
		CreatedAt:    time.Now(),
	}

	// Use repository's transaction method / Используем транзакционный метод репозитория
	repo, ok := s.auditRepo.(*postgres.AuditLogRepository)
	if !ok {
		return apperror.Internal("invalid repository type", nil)
	}
	if err := repo.CreateTx(ctx, tx, auditLog); err != nil {
		log.Error("failed to create audit log in transaction", "action", action, "error", err)
		return err
	}

	log.Debug("audit log created in transaction", "action", action, "resource_type", resourceType, "resource_id", resourceID)
	return nil
}

// GetUserAuditLogs retrieves recent audit log entries for a user.
// GetUserAuditLogs получает последние записи аудит-лога для пользователя.
func (s *AuditService) GetUserAuditLogs(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error) {
	if limit <= 0 {
		limit = 50 // Default limit / Лимит по умолчанию
	}
	return s.auditRepo.FindByUserID(ctx, userID, limit)
}
