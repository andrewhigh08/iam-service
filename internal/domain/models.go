// Package domain contains core business entities and value objects.
// Пакет domain содержит основные бизнес-сущности и объекты-значения.
package domain

import (
	"encoding/json"
	"time"
)

// Password type constants define the type of user password.
// Константы типов паролей определяют тип пароля пользователя.
const (
	// PasswordTypePermanent indicates a regular permanent password.
	// PasswordTypePermanent указывает на обычный постоянный пароль.
	PasswordTypePermanent = "permanent"

	// PasswordTypeOneTime indicates a temporary password that must be changed on first login.
	// PasswordTypeOneTime указывает на временный пароль, который необходимо сменить при первом входе.
	PasswordTypeOneTime = "onetime"
)

// Audit action constants for authentication events.
// Константы действий аудита для событий аутентификации.
const (
	// AuditActionLoginSuccess indicates a successful login.
	// AuditActionLoginSuccess указывает на успешный вход.
	AuditActionLoginSuccess = "auth.login.success"

	// AuditActionLoginFailed indicates a failed login attempt.
	// AuditActionLoginFailed указывает на неудачную попытку входа.
	AuditActionLoginFailed = "auth.login.failed"

	// AuditActionLoginLocked indicates a login attempt on a locked account.
	// AuditActionLoginLocked указывает на попытку входа в заблокированный аккаунт.
	AuditActionLoginLocked = "auth.login.locked"

	// AuditActionLogout indicates a user logout.
	// AuditActionLogout указывает на выход пользователя.
	AuditActionLogout = "auth.logout"

	// AuditActionLogoutAll indicates a logout from all devices.
	// AuditActionLogoutAll указывает на выход со всех устройств.
	AuditActionLogoutAll = "auth.logout.all"

	// AuditActionPasswordChange indicates a password change.
	// AuditActionPasswordChange указывает на смену пароля.
	AuditActionPasswordChange = "auth.password.change"

	// AuditActionPasswordChangeFirstTime indicates a first-time password change.
	// AuditActionPasswordChangeFirstTime указывает на первую смену пароля.
	AuditActionPasswordChangeFirstTime = "auth.password.change.first"

	// AuditActionPasswordExpired indicates a login with expired password.
	// AuditActionPasswordExpired указывает на вход с истёкшим паролем.
	AuditActionPasswordExpired = "auth.password.expired"

	// AuditActionTokenRefresh indicates a token refresh.
	// AuditActionTokenRefresh указывает на обновление токена.
	AuditActionTokenRefresh = "auth.token.refresh" //nolint:gosec // G101: This is an audit action name, not credentials

	// AuditActionSessionRevoke indicates a session was manually revoked.
	// AuditActionSessionRevoke указывает на ручной отзыв сессии.
	AuditActionSessionRevoke = "auth.session.revoke"
)

// Audit resource type constants.
// Константы типов ресурсов аудита.
const (
	// AuditResourceTypeAuth represents authentication resource type.
	// AuditResourceTypeAuth представляет тип ресурса аутентификации.
	AuditResourceTypeAuth = "auth"

	// AuditResourceTypeUser represents user resource type.
	// AuditResourceTypeUser представляет тип ресурса пользователя.
	AuditResourceTypeUser = "user"
)

// User represents a user entity in the system.
// User представляет сущность пользователя в системе.
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
//
// Поля:
//   - ID: Уникальный идентификатор (первичный ключ)
//   - Email: Email адрес пользователя (уникальный, используется для аутентификации)
//   - PasswordHash: Bcrypt хэш пароля пользователя
//   - PasswordType: Тип пароля (постоянный или одноразовый)
//   - PasswordChangedAt: Временная метка последней смены пароля (для проверки срока действия)
//   - FullName: Полное имя пользователя для отображения
//   - IsBlocked: Заблокирован ли пользователь в системе
//   - CreatedAt: Временная метка создания пользователя
//   - UpdatedAt: Временная метка последнего обновления
//   - DeletedAt: Временная метка мягкого удаления (nil если не удалён)
type User struct {
	ID                int64      `gorm:"primaryKey"`                           // Primary key / Первичный ключ
	Email             string     `gorm:"uniqueIndex;not null"`                 // Unique email / Уникальный email
	PasswordHash      string     `gorm:"not null"`                             // Bcrypt hash / Bcrypt хэш
	PasswordType      string     `gorm:"type:varchar(20);default:'permanent'"` // Password type / Тип пароля
	PasswordChangedAt *time.Time `gorm:""`                                     // Last password change / Последняя смена пароля
	FullName          string     `gorm:"type:varchar(255)"`                    // Display name / Отображаемое имя
	IsBlocked         bool       `gorm:"default:false"`                        // Block status / Статус блокировки
	CreatedAt         time.Time  `gorm:"not null"`                             // Creation time / Время создания
	UpdatedAt         time.Time  `gorm:"not null"`                             // Update time / Время обновления
	DeletedAt         *time.Time `gorm:"index"`                                // Soft delete / Мягкое удаление
}

// TableName returns the database table name for User entity.
// TableName возвращает имя таблицы в базе данных для сущности User.
func (User) TableName() string {
	return "users"
}

// AuditLog represents an audit log entry for tracking user actions.
// AuditLog представляет запись аудит-лога для отслеживания действий пользователей.
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
//
// Поля:
//   - ID: Уникальный идентификатор (первичный ключ)
//   - UserID: ID пользователя, выполнившего действие
//   - Action: Тип выполненного действия (например, "user.create", "auth.login")
//   - ResourceType: Тип затронутого ресурса (например, "user", "role")
//   - ResourceID: ID затронутого ресурса
//   - Details: Дополнительные JSON-детали о действии
//   - IPAddress: IP-адрес, с которого выполнено действие
//   - UserAgent: User agent строка клиента
//   - CreatedAt: Временная метка выполнения действия
type AuditLog struct {
	ID           int64           `gorm:"primaryKey"`                       // Primary key / Первичный ключ
	UserID       int64           `gorm:"not null;index:idx_audit_user"`    // User reference / Ссылка на пользователя
	Action       string          `gorm:"type:varchar(100);not null"`       // Action type / Тип действия
	ResourceType string          `gorm:"type:varchar(50)"`                 // Resource type / Тип ресурса
	ResourceID   string          `gorm:"type:varchar(50)"`                 // Resource ID / ID ресурса
	Details      json.RawMessage `gorm:"type:jsonb"`                       // JSON details / JSON детали
	IPAddress    *string         `gorm:"type:inet"`                        // Client IP / IP клиента
	UserAgent    *string         `gorm:"type:text"`                        // Client user agent / User agent клиента
	CreatedAt    time.Time       `gorm:"not null;index:idx_audit_created"` // Creation time / Время создания
}

// TableName returns the database table name for AuditLog entity.
// TableName возвращает имя таблицы в базе данных для сущности AuditLog.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// CreateUserRequest represents a request to create a new user.
// CreateUserRequest представляет запрос на создание нового пользователя.
//
// Validation rules / Правила валидации:
//   - Email: Required, must be valid email format / Обязательно, должен быть валидным email
//   - Password: Required, minimum 8 characters / Обязательно, минимум 8 символов
//   - FullName: Required / Обязательно
//   - Role: Required, must be one of: admin, analyst, viewer / Обязательно, одно из: admin, analyst, viewer
//   - PasswordType: Optional, defaults to permanent / Опционально, по умолчанию permanent
type CreateUserRequest struct {
	Email        string `json:"email" binding:"required,email"`                            // User email / Email пользователя
	Password     string `json:"password" binding:"required,min=8"`                         // Initial password / Начальный пароль
	FullName     string `json:"full_name" binding:"required"`                              // Full name / Полное имя
	Role         string `json:"role" binding:"required,oneof=admin analyst viewer"`        // User role / Роль пользователя
	PasswordType string `json:"password_type" binding:"omitempty,oneof=permanent onetime"` // Password type / Тип пароля
}

// ChangePasswordRequest represents a request to change the current user's password.
// ChangePasswordRequest представляет запрос на смену пароля текущего пользователя.
//
// Validation rules / Правила валидации:
//   - OldPassword: Required, current password for verification / Обязательно, текущий пароль для проверки
//   - NewPassword: Required, minimum 8 characters / Обязательно, минимум 8 символов
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`       // Current password / Текущий пароль
	NewPassword string `json:"new_password" binding:"required,min=8"` // New password / Новый пароль
}

// FirstTimePasswordChangeRequest represents a request to change a temporary password.
// FirstTimePasswordChangeRequest представляет запрос на смену временного пароля.
//
// This is used when a user logs in with a one-time password and must set a new permanent password.
// Используется, когда пользователь входит с одноразовым паролем и должен установить новый постоянный пароль.
//
// Validation rules / Правила валидации:
//   - UserID: Required, ID of the user changing password / Обязательно, ID пользователя
//   - OldPassword: Required, temporary password / Обязательно, временный пароль
//   - NewPassword: Required, minimum 8 characters / Обязательно, минимум 8 символов
type FirstTimePasswordChangeRequest struct {
	UserID      int64  `json:"user_id" binding:"required"`            // User ID / ID пользователя
	OldPassword string `json:"old_password" binding:"required"`       // Temporary password / Временный пароль
	NewPassword string `json:"new_password" binding:"required,min=8"` // New permanent password / Новый постоянный пароль
}

// Session represents an active user session (refresh token).
// Session представляет активную сессию пользователя (refresh token).
//
// Fields:
//   - ID: Short session identifier for display (first 8 chars of token hash)
//   - TokenID: Full token identifier (used internally for revocation)
//   - CreatedAt: Approximate session creation time
//   - ExpiresAt: Session expiration time
//   - IsCurrent: Whether this is the current session making the request
//
// Поля:
//   - ID: Короткий идентификатор сессии для отображения (первые 8 символов хэша)
//   - TokenID: Полный идентификатор токена (используется для отзыва)
//   - CreatedAt: Примерное время создания сессии
//   - ExpiresAt: Время истечения сессии
//   - IsCurrent: Является ли эта сессия текущей
type Session struct {
	ID        string    `json:"id"`                   // Short identifier / Короткий идентификатор
	TokenID   string    `json:"-"`                    // Full token ID (not exposed in JSON) / Полный ID токена
	CreatedAt time.Time `json:"created_at"`           // Creation time / Время создания
	ExpiresAt time.Time `json:"expires_at"`           // Expiration time / Время истечения
	IsCurrent bool      `json:"is_current,omitempty"` // Is current session / Текущая ли сессия
}
