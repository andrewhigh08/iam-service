// Package port defines interfaces (ports) for the application's external dependencies.
// Пакет port определяет интерфейсы (порты) для внешних зависимостей приложения.
//
// This package follows the Hexagonal Architecture (Ports and Adapters) pattern,
// where ports define the contracts that adapters must implement.
// Этот пакет следует паттерну Гексагональной Архитектуры (Порты и Адаптеры),
// где порты определяют контракты, которые должны реализовывать адаптеры.
package port

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// UserFilter defines filtering options for user queries.
// UserFilter определяет параметры фильтрации для запросов пользователей.
//
// Fields / Поля:
//   - Status: Filter by user status ("active", "blocked", "all")
//     Фильтр по статусу пользователя ("active", "blocked", "all")
//   - Search: Search string for email or full name
//     Строка поиска по email или полному имени
//   - Page: Page number for pagination (1-based)
//     Номер страницы для пагинации (начиная с 1)
//   - PageSize: Number of items per page
//     Количество элементов на странице
type UserFilter struct {
	Status   string // "active", "blocked", "all" / "active", "blocked", "all"
	Search   string // Search by email or full name / Поиск по email или имени
	Page     int    // Page number / Номер страницы
	PageSize int    // Items per page / Элементов на странице
}

// UserRepository defines the interface for user data access operations.
// UserRepository определяет интерфейс для операций доступа к данным пользователей.
//
// This interface abstracts the data storage layer, allowing different
// implementations (PostgreSQL, MySQL, etc.) to be used interchangeably.
// Этот интерфейс абстрагирует слой хранения данных, позволяя использовать
// различные реализации (PostgreSQL, MySQL и др.) взаимозаменяемо.
type UserRepository interface {
	// Create creates a new user in the database.
	// Create создаёт нового пользователя в базе данных.
	Create(ctx context.Context, user *domain.User) error

	// CreateTx creates a new user within an existing database transaction.
	// CreateTx создаёт нового пользователя в рамках существующей транзакции БД.
	CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error

	// FindByID retrieves a user by their unique identifier.
	// FindByID получает пользователя по уникальному идентификатору.
	// Returns nil if user is not found.
	// Возвращает nil, если пользователь не найден.
	FindByID(ctx context.Context, id int64) (*domain.User, error)

	// FindByEmail retrieves a user by their email address.
	// FindByEmail получает пользователя по email адресу.
	// Returns nil if user is not found.
	// Возвращает nil, если пользователь не найден.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// Update updates an existing user's information.
	// Update обновляет информацию существующего пользователя.
	Update(ctx context.Context, user *domain.User) error

	// UpdateTx updates an existing user within a transaction.
	// UpdateTx обновляет пользователя в рамках транзакции.
	UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error

	// Delete performs a soft delete on a user (sets deleted_at timestamp).
	// Delete выполняет мягкое удаление пользователя (устанавливает deleted_at).
	Delete(ctx context.Context, id int64) error

	// DeleteTx performs a soft delete within a transaction.
	// DeleteTx выполняет мягкое удаление в рамках транзакции.
	DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error

	// List retrieves users with filtering and pagination support.
	// List получает пользователей с поддержкой фильтрации и пагинации.
	// Returns the list of users, total count, and any error.
	// Возвращает список пользователей, общее количество и ошибку.
	List(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)

	// ExistsByEmail checks if a user with the given email already exists.
	// ExistsByEmail проверяет, существует ли пользователь с указанным email.
	ExistsByEmail(ctx context.Context, email string) (bool, error)
}

// AuditLogRepository defines the interface for audit log data access.
// AuditLogRepository определяет интерфейс для доступа к данным аудит-логов.
//
// Audit logs track all significant actions in the system for compliance
// and security purposes.
// Аудит-логи отслеживают все значимые действия в системе для целей
// соответствия требованиям и безопасности.
type AuditLogRepository interface {
	// Create creates a new audit log entry.
	// Create создаёт новую запись аудит-лога.
	Create(ctx context.Context, log *domain.AuditLog) error

	// CreateTx creates a new audit log entry within a transaction.
	// CreateTx создаёт запись аудит-лога в рамках транзакции.
	CreateTx(ctx context.Context, tx *gorm.DB, log *domain.AuditLog) error

	// FindByUserID retrieves recent audit logs for a specific user.
	// FindByUserID получает последние записи аудит-лога для пользователя.
	FindByUserID(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error)

	// FindByResourceID retrieves audit logs for a specific resource.
	// FindByResourceID получает записи аудит-лога для конкретного ресурса.
	FindByResourceID(ctx context.Context, resourceType string, resourceID string, limit int) ([]domain.AuditLog, error)
}

// Transaction provides database transaction support.
// Transaction обеспечивает поддержку транзакций базы данных.
//
// Transactions ensure data consistency when multiple operations
// need to be performed atomically.
// Транзакции обеспечивают согласованность данных, когда несколько операций
// должны выполняться атомарно.
type Transaction interface {
	// Begin starts a new database transaction.
	// Begin начинает новую транзакцию базы данных.
	Begin(ctx context.Context) (*gorm.DB, error)

	// Commit commits a transaction, making all changes permanent.
	// Commit фиксирует транзакцию, делая все изменения постоянными.
	Commit(tx *gorm.DB) error

	// Rollback rolls back a transaction, discarding all changes.
	// Rollback откатывает транзакцию, отменяя все изменения.
	Rollback(tx *gorm.DB) error

	// WithTransaction executes a function within a transaction.
	// WithTransaction выполняет функцию в рамках транзакции.
	// Automatically commits on success or rolls back on error.
	// Автоматически фиксирует при успехе или откатывает при ошибке.
	WithTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error
}
