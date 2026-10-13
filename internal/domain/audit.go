package domain

import (
	"encoding/json"
	"time"
)

// Audit actions recorded by the service layer.
const (
	AuditActionLoginSuccess   = "auth.login.success"
	AuditActionLoginFailed    = "auth.login.failed"
	AuditActionLoginLocked    = "auth.login.locked"
	AuditActionLogout         = "auth.logout"
	AuditActionLogoutAll      = "auth.logout_all"
	AuditActionTokenRefresh   = "auth.token.refresh" //nolint:gosec // G101: audit action name, not a credential
	AuditActionTokenReuse     = "auth.token.reuse"   //nolint:gosec // G101: audit action name, not a credential
	AuditActionPasswordChange = "auth.password.change"
	AuditActionSessionRevoke  = "auth.session.revoke"
	AuditActionUserCreate     = "user.create"
	AuditActionUserBlock      = "user.block"
	AuditActionUserUnblock    = "user.unblock"
)

// AuditResourceTypeUser is the resource type of audit entries about a user account.
const AuditResourceTypeUser = "user"

// AuditLog is a persisted audit entry.
type AuditLog struct {
	ID           int64           `gorm:"primaryKey"`
	ActorID      int64           `gorm:"not null"`
	Action       string          `gorm:"not null"`
	ResourceType string          `gorm:"not null"`
	ResourceID   string          `gorm:"not null"`
	Details      json.RawMessage `gorm:"type:jsonb"`
	IPAddress    *string         `gorm:"type:inet"`
	UserAgent    *string         `gorm:"type:text"`
	CreatedAt    time.Time       `gorm:"not null"`
}

// TableName returns the audit_logs table name.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// AuditEvent describes an action to record. Details are serialized to JSON by the audit service.
type AuditEvent struct {
	ActorID      int64
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]any
	ClientMeta
}
