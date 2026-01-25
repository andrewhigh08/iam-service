// Package postgres provides PostgreSQL-based repository implementations.
// Пакет postgres предоставляет реализации репозиториев на базе PostgreSQL.
package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// TransactionManager implements port.Transaction interface using GORM.
// TransactionManager реализует интерфейс port.Transaction с использованием GORM.
//
// Provides transaction management capabilities for coordinating
// multiple database operations atomically.
// Предоставляет возможности управления транзакциями для координации
// нескольких операций с базой данных атомарно.
type TransactionManager struct {
	db *gorm.DB // Database connection / Подключение к базе данных
}

// NewTransactionManager creates a new TransactionManager instance.
// NewTransactionManager создаёт новый экземпляр TransactionManager.
func NewTransactionManager(db *gorm.DB) *TransactionManager {
	return &TransactionManager{db: db}
}

// Begin starts a new database transaction.
// Begin начинает новую транзакцию базы данных.
// Returns a transaction handle that must be committed or rolled back.
// Возвращает дескриптор транзакции, который должен быть зафиксирован или откачен.
func (t *TransactionManager) Begin(ctx context.Context) (*gorm.DB, error) {
	tx := t.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, apperror.Internal("failed to begin transaction", tx.Error)
	}
	return tx, nil
}

// Commit commits a transaction.
// Commit фиксирует транзакцию.
// All changes made within the transaction become permanent.
// Все изменения, сделанные в рамках транзакции, становятся постоянными.
func (t *TransactionManager) Commit(tx *gorm.DB) error {
	if err := tx.Commit().Error; err != nil {
		return apperror.Internal("failed to commit transaction", err)
	}
	return nil
}

// Rollback rolls back a transaction.
// Rollback откатывает транзакцию.
// All changes made within the transaction are discarded.
// Все изменения, сделанные в рамках транзакции, отменяются.
func (t *TransactionManager) Rollback(tx *gorm.DB) error {
	if err := tx.Rollback().Error; err != nil {
		return apperror.Internal("failed to rollback transaction", err)
	}
	return nil
}

// WithTransaction executes a function within a transaction.
// WithTransaction выполняет функцию в рамках транзакции.
// Automatically commits on success or rolls back on error/panic.
// Автоматически фиксирует при успехе или откатывает при ошибке/панике.
//
// Example usage / Пример использования:
//
//	err := tm.WithTransaction(ctx, func(tx *gorm.DB) error {
//	    if err := userRepo.CreateTx(ctx, tx, user); err != nil {
//	        return err
//	    }
//	    return auditRepo.CreateTx(ctx, tx, auditLog)
//	})
func (t *TransactionManager) WithTransaction(ctx context.Context, fn func(tx *gorm.DB) error) error {
	tx := t.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return apperror.Internal("failed to begin transaction", tx.Error)
	}

	// Ensure rollback on panic / Гарантируем откат при панике
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r) // Re-throw panic / Повторно выбрасываем панику
		}
	}()

	// Execute the function / Выполняем функцию
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback().Error; rbErr != nil {
			return apperror.Internal("failed to rollback transaction", rbErr)
		}
		return err
	}

	// Commit the transaction / Фиксируем транзакцию
	if err := tx.Commit().Error; err != nil {
		return apperror.Internal("failed to commit transaction", err)
	}
	return nil
}

// DB returns the underlying database connection.
// DB возвращает базовое подключение к базе данных.
// Use this when you need direct access to the database outside of transactions.
// Используйте, когда нужен прямой доступ к базе данных вне транзакций.
func (t *TransactionManager) DB() *gorm.DB {
	return t.db
}
