// Package port defines interfaces (ports) for the application's external dependencies.
package port

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// TokenPair contains both access and refresh tokens.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthService defines the interface for authentication operations.
//
// This service handles user authentication, token generation and validation,
// and password management.
type AuthService interface {
	// Login authenticates a user with email and password.
	// Returns token pair, flag indicating if OTP change is required, and error.
	Login(ctx context.Context, email, password string) (tokens *TokenPair, isOTP bool, err error)

	// RefreshToken validates refresh token and returns new access token.
	RefreshToken(ctx context.Context, refreshToken string) (accessToken string, err error)

	// Logout invalidates refresh token and optionally blacklists access token.
	Logout(ctx context.Context, refreshToken, accessToken string) error

	// LogoutAll invalidates all refresh tokens for a user and blacklists current access token.
	LogoutAll(ctx context.Context, userID int64, accessToken string) error

	// IsTokenBlacklisted checks if a token is in the blacklist by its JTI.
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)

	// ValidateToken validates a JWT token and extracts claims.
	// Returns nil error if token is valid.
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)

	// ChangePassword changes the password for an authenticated user.
	// Requires the old password for verification.
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error

	// FirstTimePasswordChange changes a one-time password to a permanent one.
	// Must be called when user logs in with OTP password.
	FirstTimePasswordChange(ctx context.Context, userID int64, oldPassword, newPassword string) error

	// GetUserByEmail retrieves a user by their email address.
	// Used for OTP flow to get user ID after login.
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)

	// GenerateTokenForUser generates a JWT token pair for a specific user.
	// Used after first-time password change.
	GenerateTokenForUser(ctx context.Context, userID int64) (*TokenPair, error)

	// GetPublicKey returns the RSA public key for external token verification.
	GetPublicKey() interface{}

	// GetUserSessions retrieves all active sessions (refresh tokens) for a user.
	// currentTokenID is used to mark the current session; can be empty.
	GetUserSessions(ctx context.Context, userID int64, currentTokenID string) ([]domain.Session, error)

	// RevokeSession revokes a specific session by its token ID.
	RevokeSession(ctx context.Context, userID int64, tokenID string) error
}

// Claims represents JWT token claims containing user information.
//
// These claims are embedded in every JWT token and used for
// authentication and authorization decisions.
type Claims struct {
	UserID               int64    `json:"user_id"` // User's unique ID
	Email                string   `json:"email"`   // User's email
	Roles                []string `json:"roles"`   // User's roles
	jwt.RegisteredClaims          // Standard JWT claims
}

// UserService defines the interface for user management operations.
//
// This service handles CRUD operations for users, including
// creation, retrieval, blocking, and unblocking.
type UserService interface {
	// CreateUser creates a new user with the specified role.
	// Also logs the action to the audit trail.
	CreateUser(ctx context.Context, req *domain.CreateUserRequest, createdBy int64, ipAddress, userAgent string) (*domain.User, error)

	// GetUserByID retrieves a user by their unique identifier.
	GetUserByID(ctx context.Context, id int64) (*domain.User, error)

	// ListUsers retrieves a paginated list of users with optional filtering.
	// Returns users, total count, and error.
	ListUsers(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)

	// BlockUser blocks a user account, preventing login.
	BlockUser(ctx context.Context, id int64, blockedBy int64, ipAddress, userAgent string) error

	// UnblockUser unblocks a previously blocked user account.
	UnblockUser(ctx context.Context, id int64, unblockedBy int64, ipAddress, userAgent string) error
}

// AuthorizationService defines the interface for RBAC authorization operations.
//
// This service implements Role-Based Access Control using Casbin,
// with support for caching authorization decisions.
type AuthorizationService interface {
	// CheckAccess verifies if a user can perform an action on a resource.
	// Returns true if access is allowed, false otherwise.
	CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error)

	// AddRoleToUser assigns a role to a user.
	AddRoleToUser(ctx context.Context, userID int64, role string) error

	// RemoveRoleFromUser removes a role from a user.
	RemoveRoleFromUser(ctx context.Context, userID int64, role string) error

	// GetUserRoles retrieves all roles assigned to a user.
	GetUserRoles(ctx context.Context, userID int64) ([]string, error)

	// ReloadPolicies reloads RBAC policies from the database.
	// Call this after policy changes.
	ReloadPolicies(ctx context.Context) error
}

// AuditService defines the interface for audit logging operations.
//
// Audit logging tracks all significant user actions for security,
// compliance, and debugging purposes.
type AuditService interface {
	// LogAction logs an action to the audit trail.
	LogAction(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error

	// LogActionTx logs an action within an existing transaction.
	LogActionTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error

	// LogActionWithContext logs an action with IP address and user agent.
	LogActionWithContext(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error

	// LogActionWithContextTx logs an action with context within a transaction.
	LogActionWithContextTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error

	// GetUserAuditLogs retrieves recent audit log entries for a user.
	GetUserAuditLogs(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error)
}
