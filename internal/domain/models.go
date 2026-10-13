// Package domain contains core business entities and value objects.
package domain

import (
	"encoding/json"
	"time"
)

// Password type constants define the type of user password.
const (
	// PasswordTypePermanent indicates a regular permanent password.
	PasswordTypePermanent = "permanent"

	// PasswordTypeOneTime indicates a temporary password that must be changed on first login.
	PasswordTypeOneTime = "onetime"
)

// Audit action constants for authentication events.
const (
	// AuditActionLoginSuccess indicates a successful login.
	AuditActionLoginSuccess = "auth.login.success"

	// AuditActionLoginFailed indicates a failed login attempt.
	AuditActionLoginFailed = "auth.login.failed"

	// AuditActionLoginLocked indicates a login attempt on a locked account.
	AuditActionLoginLocked = "auth.login.locked"

	// AuditActionLogout indicates a user logout.
	AuditActionLogout = "auth.logout"

	// AuditActionLogoutAll indicates a logout from all devices.
	AuditActionLogoutAll = "auth.logout.all"

	// AuditActionPasswordChange indicates a password change.
	AuditActionPasswordChange = "auth.password.change"

	// AuditActionPasswordChangeFirstTime indicates a first-time password change.
	AuditActionPasswordChangeFirstTime = "auth.password.change.first"

	// AuditActionPasswordExpired indicates a login with expired password.
	AuditActionPasswordExpired = "auth.password.expired"

	// AuditActionTokenRefresh indicates a token refresh.
	AuditActionTokenRefresh = "auth.token.refresh" //nolint:gosec // G101: This is an audit action name, not credentials

	// AuditActionSessionRevoke indicates a session was manually revoked.
	AuditActionSessionRevoke = "auth.session.revoke"
)

// Audit resource type constants.
const (
	// AuditResourceTypeAuth represents authentication resource type.
	AuditResourceTypeAuth = "auth"

	// AuditResourceTypeUser represents user resource type.
	AuditResourceTypeUser = "user"
)

// User represents a user entity in the system.
//
// Fields:
//   - ID: Unique identifier (primary key)
//   - Email: User's email address (unique, used for authentication)
//   - PasswordHash: Bcrypt hash of the user's password
//   - PasswordType: Type of password (permanent or onetime)
//   - PasswordChangedAt: Timestamp when the password was last changed (for expiration check)
//   - FullName: User's full name for display purposes
//   - IsBlocked: Whether the user is blocked from accessing the system
//   - CreatedAt: Timestamp when the user was created
//   - UpdatedAt: Timestamp when the user was last updated
//   - DeletedAt: Soft delete timestamp (nil if not deleted)
type User struct {
	ID                int64      `gorm:"primaryKey"`                           // Primary key
	Email             string     `gorm:"uniqueIndex;not null"`                 // Unique email
	PasswordHash      string     `gorm:"not null"`                             // Bcrypt hash
	PasswordType      string     `gorm:"type:varchar(20);default:'permanent'"` // Password type
	PasswordChangedAt *time.Time `gorm:""`                                     // Last password change
	FullName          string     `gorm:"type:varchar(255)"`                    // Display name
	IsBlocked         bool       `gorm:"default:false"`                        // Block status
	CreatedAt         time.Time  `gorm:"not null"`                             // Creation time
	UpdatedAt         time.Time  `gorm:"not null"`                             // Update time
	DeletedAt         *time.Time `gorm:"index"`                                // Soft delete
}

// TableName returns the database table name for User entity.
func (User) TableName() string {
	return "users"
}

// AuditLog represents an audit log entry for tracking user actions.
//
// Fields:
//   - ID: Unique identifier (primary key)
//   - UserID: ID of the user who performed the action
//   - Action: Type of action performed (e.g., "user.create", "auth.login")
//   - ResourceType: Type of resource affected (e.g., "user", "role")
//   - ResourceID: ID of the affected resource
//   - Details: Additional JSON details about the action
//   - IPAddress: IP address from which the action was performed
//   - UserAgent: User agent string of the client
//   - CreatedAt: Timestamp when the action occurred
type AuditLog struct {
	ID           int64           `gorm:"primaryKey"`                       // Primary key
	UserID       int64           `gorm:"not null;index:idx_audit_user"`    // User reference
	Action       string          `gorm:"type:varchar(100);not null"`       // Action type
	ResourceType string          `gorm:"type:varchar(50)"`                 // Resource type
	ResourceID   string          `gorm:"type:varchar(50)"`                 // Resource ID
	Details      json.RawMessage `gorm:"type:jsonb"`                       // JSON details
	IPAddress    *string         `gorm:"type:inet"`                        // Client IP
	UserAgent    *string         `gorm:"type:text"`                        // Client user agent
	CreatedAt    time.Time       `gorm:"not null;index:idx_audit_created"` // Creation time
}

// TableName returns the database table name for AuditLog entity.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// CreateUserRequest represents a request to create a new user.
//
// Validation rules:
//   - Email: Required, must be valid email format
//   - Password: Required, minimum 8 characters
//   - FullName: Required
//   - Role: Required, must be one of: admin, analyst, viewer
//   - PasswordType: Optional, defaults to permanent
type CreateUserRequest struct {
	Email        string `json:"email" binding:"required,email"`                            // User email
	Password     string `json:"password" binding:"required,min=8"`                         // Initial password
	FullName     string `json:"full_name" binding:"required"`                              // Full name
	Role         string `json:"role" binding:"required,oneof=admin analyst viewer"`        // User role
	PasswordType string `json:"password_type" binding:"omitempty,oneof=permanent onetime"` // Password type
}

// ChangePasswordRequest represents a request to change the current user's password.
//
// Validation rules:
//   - OldPassword: Required, current password for verification
//   - NewPassword: Required, minimum 8 characters
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`       // Current password
	NewPassword string `json:"new_password" binding:"required,min=8"` // New password
}

// FirstTimePasswordChangeRequest represents a request to change a temporary password.
//
// This is used when a user logs in with a one-time password and must set a new permanent password.
//
// Validation rules:
//   - UserID: Required, ID of the user changing password
//   - OldPassword: Required, temporary password
//   - NewPassword: Required, minimum 8 characters
type FirstTimePasswordChangeRequest struct {
	UserID      int64  `json:"user_id" binding:"required"`            // User ID
	OldPassword string `json:"old_password" binding:"required"`       // Temporary password
	NewPassword string `json:"new_password" binding:"required,min=8"` // New permanent password
}

// Session represents an active user session (refresh token).
//
// Fields:
//   - ID: Short session identifier for display (first 8 chars of token hash)
//   - TokenID: Full token identifier (used internally for revocation)
//   - CreatedAt: Approximate session creation time
//   - ExpiresAt: Session expiration time
//   - IsCurrent: Whether this is the current session making the request
type Session struct {
	ID        string    `json:"id"`                   // Short identifier
	TokenID   string    `json:"-"`                    // Full token ID (not exposed in JSON)
	CreatedAt time.Time `json:"created_at"`           // Creation time
	ExpiresAt time.Time `json:"expires_at"`           // Expiration time
	IsCurrent bool      `json:"is_current,omitempty"` // Is current session
}
