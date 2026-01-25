// Package postgres provides PostgreSQL-based repository implementations.
// Пакет postgres предоставляет реализации репозиториев на базе PostgreSQL.
//
// This package implements all repository interfaces defined in port package
// using GORM as the ORM layer.
// Этот пакет реализует все интерфейсы репозиториев, определённые в пакете port,
// используя GORM в качестве ORM слоя.
package postgres

import (
	"context"
	"errors"
	"strings"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// UserRepository implements port.UserRepository using PostgreSQL.
// UserRepository реализует интерфейс port.UserRepository с использованием PostgreSQL.
//
// Provides CRUD operations for user entities with support for
// soft delete and transactional operations.
// Предоставляет CRUD операции для сущностей пользователей с поддержкой
// мягкого удаления и транзакционных операций.
type UserRepository struct {
	db *gorm.DB // Database connection / Подключение к базе данных
}

// NewUserRepository creates a new UserRepository instance.
// NewUserRepository создаёт новый экземпляр UserRepository.
func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user in the database.
// Create создаёт нового пользователя в базе данных.
func (r *UserRepository) Create(ctx context.Context, user *domain.User) error {
	return r.CreateTx(ctx, r.db, user)
}

// CreateTx creates a new user within an existing transaction.
// CreateTx создаёт нового пользователя в рамках существующей транзакции.
// Use this when creating a user as part of a larger transactional operation.
// Используйте, когда создание пользователя является частью большой транзакции.
func (r *UserRepository) CreateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	if err := tx.WithContext(ctx).Create(user).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) || isDuplicateKeyError(err) {
			return apperror.Conflict("user", "email", user.Email)
		}
		return apperror.Internal("failed to create user", err)
	}
	return nil
}

// FindByID retrieves a user by their unique identifier.
// FindByID получает пользователя по уникальному идентификатору.
// Excludes soft-deleted users.
// Исключает мягко удалённых пользователей.
func (r *UserRepository) FindByID(ctx context.Context, id int64) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NotFound("user", id)
		}
		return nil, apperror.Internal("failed to find user", err)
	}
	return &user, nil
}

// FindByEmail retrieves a user by their email address.
// FindByEmail получает пользователя по адресу электронной почты.
// Excludes soft-deleted users.
// Исключает мягко удалённых пользователей.
func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	var user domain.User
	err := r.db.WithContext(ctx).
		Where("email = ? AND deleted_at IS NULL", email).
		First(&user).Error

	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, apperror.NotFound("user", email)
		}
		return nil, apperror.Internal("failed to find user", err)
	}
	return &user, nil
}

// Update updates an existing user in the database.
// Update обновляет существующего пользователя в базе данных.
func (r *UserRepository) Update(ctx context.Context, user *domain.User) error {
	return r.UpdateTx(ctx, r.db, user)
}

// UpdateTx updates an existing user within an existing transaction.
// UpdateTx обновляет существующего пользователя в рамках существующей транзакции.
func (r *UserRepository) UpdateTx(ctx context.Context, tx *gorm.DB, user *domain.User) error {
	result := tx.WithContext(ctx).Save(user)
	if result.Error != nil {
		return apperror.Internal("failed to update user", result.Error)
	}
	if result.RowsAffected == 0 {
		return apperror.NotFound("user", user.ID)
	}
	return nil
}

// Delete performs a soft-delete on a user.
// Delete выполняет мягкое удаление пользователя.
// The user record is not physically removed from the database.
// Запись пользователя физически не удаляется из базы данных.
func (r *UserRepository) Delete(ctx context.Context, id int64) error {
	return r.DeleteTx(ctx, r.db, id)
}

// DeleteTx performs a soft-delete within an existing transaction.
// DeleteTx выполняет мягкое удаление в рамках существующей транзакции.
func (r *UserRepository) DeleteTx(ctx context.Context, tx *gorm.DB, id int64) error {
	result := tx.WithContext(ctx).
		Where("id = ? AND deleted_at IS NULL", id).
		Delete(&domain.User{})

	if result.Error != nil {
		return apperror.Internal("failed to delete user", result.Error)
	}
	if result.RowsAffected == 0 {
		return apperror.NotFound("user", id)
	}
	return nil
}

// HardDelete permanently removes a user from the database.
// HardDelete физически удаляет пользователя из базы данных.
// Used for compensating transactions in saga pattern.
// Используется для компенсирующих транзакций в паттерне saga.
func (r *UserRepository) HardDelete(ctx context.Context, id int64) error {
	result := r.db.WithContext(ctx).Unscoped().Delete(&domain.User{}, id)
	if result.Error != nil {
		return apperror.Internal("failed to hard delete user", result.Error)
	}
	return nil
}

// List retrieves users with filtering and pagination.
// List получает пользователей с фильтрацией и пагинацией.
// Returns: users slice, total count, error.
// Возвращает: срез пользователей, общее количество, ошибку.
func (r *UserRepository) List(ctx context.Context, filter port.UserFilter) ([]domain.User, int64, error) {
	var users []domain.User
	var total int64

	query := r.db.WithContext(ctx).Model(&domain.User{}).Where("deleted_at IS NULL")

	// Apply status filter / Применяем фильтр по статусу
	switch filter.Status {
	case "active":
		query = query.Where("is_blocked = ?", false)
	case "blocked":
		query = query.Where("is_blocked = ?", true)
	}

	// Apply search filter (email or full name) / Применяем поисковый фильтр (email или имя)
	if filter.Search != "" {
		search := "%" + filter.Search + "%"
		query = query.Where("email ILIKE ? OR full_name ILIKE ?", search, search)
	}

	// Count total matching records / Подсчитываем общее количество записей
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, apperror.Internal("failed to count users", err)
	}

	// Calculate offset for pagination / Вычисляем смещение для пагинации
	offset := (filter.Page - 1) * filter.PageSize
	if offset < 0 {
		offset = 0
	}

	// Get paginated results / Получаем результаты с пагинацией
	err := query.
		Order("created_at DESC").
		Limit(filter.PageSize).
		Offset(offset).
		Find(&users).Error

	if err != nil {
		return nil, 0, apperror.Internal("failed to list users", err)
	}

	return users, total, nil
}

// ExistsByEmail checks if a user with the given email already exists.
// ExistsByEmail проверяет, существует ли уже пользователь с данным email.
// Excludes soft-deleted users.
// Исключает мягко удалённых пользователей.
func (r *UserRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&domain.User{}).
		Where("email = ? AND deleted_at IS NULL", email).
		Count(&count).Error

	if err != nil {
		return false, apperror.Internal("failed to check email existence", err)
	}
	return count > 0, nil
}

// isDuplicateKeyError checks if the error is a PostgreSQL duplicate key violation.
// isDuplicateKeyError проверяет, является ли ошибка нарушением уникального ключа PostgreSQL.
// PostgreSQL error code 23505 indicates unique_violation.
// Код ошибки PostgreSQL 23505 указывает на unique_violation.
func isDuplicateKeyError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, gorm.ErrDuplicatedKey) {
		return true
	}
	errMsg := err.Error()
	return errMsg != "" && (strings.Contains(errMsg, "duplicate key") || strings.Contains(errMsg, "23505"))
}
