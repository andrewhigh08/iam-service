// Package port defines interfaces (ports) for the application's external dependencies.
// Пакет port определяет интерфейсы (порты) для внешних зависимостей приложения.
package port

import (
	"context"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// TokenPair contains both access and refresh tokens.
// TokenPair содержит пару access и refresh токенов.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

// AuthService defines the interface for authentication operations.
// AuthService определяет интерфейс для операций аутентификации.
//
// This service handles user authentication, token generation and validation,
// and password management.
// Этот сервис обрабатывает аутентификацию пользователей, генерацию и валидацию
// токенов, а также управление паролями.
type AuthService interface {
	// Login authenticates a user with email and password.
	// Login аутентифицирует пользователя по email и паролю.
	// Returns token pair, flag indicating if OTP change is required, and error.
	// Возвращает пару токенов, флаг необходимости смены OTP пароля и ошибку.
	Login(ctx context.Context, email, password string) (tokens *TokenPair, isOTP bool, err error)

	// RefreshToken validates refresh token and returns new access token.
	// RefreshToken проверяет refresh токен и возвращает новый access токен.
	RefreshToken(ctx context.Context, refreshToken string) (accessToken string, err error)

	// Logout invalidates refresh token and optionally blacklists access token.
	// Logout инвалидирует refresh токен и опционально добавляет access токен в blacklist.
	Logout(ctx context.Context, refreshToken, accessToken string) error

	// LogoutAll invalidates all refresh tokens for a user and blacklists current access token.
	// LogoutAll инвалидирует все refresh токены пользователя и добавляет access токен в blacklist.
	LogoutAll(ctx context.Context, userID int64, accessToken string) error

	// IsTokenBlacklisted checks if a token is in the blacklist by its JTI.
	// IsTokenBlacklisted проверяет, находится ли токен в чёрном списке по его JTI.
	IsTokenBlacklisted(ctx context.Context, jti string) (bool, error)

	// ValidateToken validates a JWT token and extracts claims.
	// ValidateToken проверяет JWT токен и извлекает claims.
	// Returns nil error if token is valid.
	// Возвращает nil ошибку, если токен валиден.
	ValidateToken(ctx context.Context, tokenString string) (*Claims, error)

	// ChangePassword changes the password for an authenticated user.
	// ChangePassword меняет пароль для аутентифицированного пользователя.
	// Requires the old password for verification.
	// Требует старый пароль для верификации.
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error

	// FirstTimePasswordChange changes a one-time password to a permanent one.
	// FirstTimePasswordChange меняет одноразовый пароль на постоянный.
	// Must be called when user logs in with OTP password.
	// Должен вызываться, когда пользователь входит с OTP паролем.
	FirstTimePasswordChange(ctx context.Context, userID int64, oldPassword, newPassword string) error

	// GetUserByEmail retrieves a user by their email address.
	// GetUserByEmail получает пользователя по email адресу.
	// Used for OTP flow to get user ID after login.
	// Используется для OTP потока для получения ID пользователя после входа.
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)

	// GenerateTokenForUser generates a JWT token pair for a specific user.
	// GenerateTokenForUser генерирует пару JWT токенов для конкретного пользователя.
	// Used after first-time password change.
	// Используется после первой смены пароля.
	GenerateTokenForUser(ctx context.Context, userID int64) (*TokenPair, error)

	// GetPublicKey returns the RSA public key for external token verification.
	// GetPublicKey возвращает публичный RSA ключ для внешней проверки токенов.
	GetPublicKey() interface{}

	// GetUserSessions retrieves all active sessions (refresh tokens) for a user.
	// GetUserSessions получает все активные сессии (refresh токены) пользователя.
	// currentTokenID is used to mark the current session; can be empty.
	// currentTokenID используется для пометки текущей сессии; может быть пустым.
	GetUserSessions(ctx context.Context, userID int64, currentTokenID string) ([]domain.Session, error)

	// RevokeSession revokes a specific session by its token ID.
	// RevokeSession отзывает конкретную сессию по её ID токена.
	RevokeSession(ctx context.Context, userID int64, tokenID string) error
}

// Claims represents JWT token claims containing user information.
// Claims представляет claims JWT токена, содержащие информацию о пользователе.
//
// These claims are embedded in every JWT token and used for
// authentication and authorization decisions.
// Эти claims встраиваются в каждый JWT токен и используются для
// принятия решений по аутентификации и авторизации.
type Claims struct {
	UserID               int64    `json:"user_id"` // User's unique ID / Уникальный ID пользователя
	Email                string   `json:"email"`   // User's email / Email пользователя
	Roles                []string `json:"roles"`   // User's roles / Роли пользователя
	jwt.RegisteredClaims          // Standard JWT claims / Стандартные JWT claims
}

// UserService defines the interface for user management operations.
// UserService определяет интерфейс для операций управления пользователями.
//
// This service handles CRUD operations for users, including
// creation, retrieval, blocking, and unblocking.
// Этот сервис обрабатывает CRUD операции для пользователей, включая
// создание, получение, блокировку и разблокировку.
type UserService interface {
	// CreateUser creates a new user with the specified role.
	// CreateUser создаёт нового пользователя с указанной ролью.
	// Also logs the action to the audit trail.
	// Также записывает действие в аудит-лог.
	CreateUser(ctx context.Context, req *domain.CreateUserRequest, createdBy int64, ipAddress, userAgent string) (*domain.User, error)

	// GetUserByID retrieves a user by their unique identifier.
	// GetUserByID получает пользователя по уникальному идентификатору.
	GetUserByID(ctx context.Context, id int64) (*domain.User, error)

	// ListUsers retrieves a paginated list of users with optional filtering.
	// ListUsers получает пагинированный список пользователей с опциональной фильтрацией.
	// Returns users, total count, and error.
	// Возвращает пользователей, общее количество и ошибку.
	ListUsers(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)

	// BlockUser blocks a user account, preventing login.
	// BlockUser блокирует учётную запись пользователя, предотвращая вход.
	BlockUser(ctx context.Context, id int64, blockedBy int64, ipAddress, userAgent string) error

	// UnblockUser unblocks a previously blocked user account.
	// UnblockUser разблокирует ранее заблокированную учётную запись.
	UnblockUser(ctx context.Context, id int64, unblockedBy int64, ipAddress, userAgent string) error
}

// AuthorizationService defines the interface for RBAC authorization operations.
// AuthorizationService определяет интерфейс для операций RBAC авторизации.
//
// This service implements Role-Based Access Control using Casbin,
// with support for caching authorization decisions.
// Этот сервис реализует управление доступом на основе ролей с помощью Casbin,
// с поддержкой кэширования решений авторизации.
type AuthorizationService interface {
	// CheckAccess verifies if a user can perform an action on a resource.
	// CheckAccess проверяет, может ли пользователь выполнить действие над ресурсом.
	// Returns true if access is allowed, false otherwise.
	// Возвращает true если доступ разрешён, false в противном случае.
	CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error)

	// AddRoleToUser assigns a role to a user.
	// AddRoleToUser назначает роль пользователю.
	AddRoleToUser(ctx context.Context, userID int64, role string) error

	// RemoveRoleFromUser removes a role from a user.
	// RemoveRoleFromUser удаляет роль у пользователя.
	RemoveRoleFromUser(ctx context.Context, userID int64, role string) error

	// GetUserRoles retrieves all roles assigned to a user.
	// GetUserRoles получает все роли, назначенные пользователю.
	GetUserRoles(ctx context.Context, userID int64) ([]string, error)

	// ReloadPolicies reloads RBAC policies from the database.
	// ReloadPolicies перезагружает политики RBAC из базы данных.
	// Call this after policy changes.
	// Вызывайте после изменения политик.
	ReloadPolicies(ctx context.Context) error
}

// AuditService defines the interface for audit logging operations.
// AuditService определяет интерфейс для операций аудит-логирования.
//
// Audit logging tracks all significant user actions for security,
// compliance, and debugging purposes.
// Аудит-логирование отслеживает все значимые действия пользователей
// для безопасности, соответствия требованиям и отладки.
type AuditService interface {
	// LogAction logs an action to the audit trail.
	// LogAction записывает действие в аудит-лог.
	LogAction(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error

	// LogActionTx logs an action within an existing transaction.
	// LogActionTx записывает действие в рамках существующей транзакции.
	LogActionTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error

	// LogActionWithContext logs an action with IP address and user agent.
	// LogActionWithContext записывает действие с IP-адресом и user agent.
	LogActionWithContext(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error

	// LogActionWithContextTx logs an action with context within a transaction.
	// LogActionWithContextTx записывает действие с контекстом в рамках транзакции.
	LogActionWithContextTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error

	// GetUserAuditLogs retrieves recent audit log entries for a user.
	// GetUserAuditLogs получает последние записи аудит-лога для пользователя.
	GetUserAuditLogs(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error)
}
