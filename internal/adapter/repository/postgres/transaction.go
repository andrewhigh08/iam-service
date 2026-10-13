// Package postgres provides PostgreSQL-based repository implementations.
package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// TransactionManager implements port.Transaction interface using GORM.
//
// Provides transaction management capabilities for coordinating
// multiple database operations atomically.
type TransactionManager struct {
	db *gorm.DB // Database connection
}

// NewTransactionManager creates a new TransactionManager instance.
func NewTransactionManager(db *gorm.DB) *TransactionManager {
	return &TransactionManager{db: db}
}

// Begin starts a new database transaction.
// Returns a transaction handle that must be committed or rolled back.
func (t *TransactionManager) Begin(ctx context.Context) (*gorm.DB, error) {
	tx := t.db.WithContext(ctx).Begin()
	if tx.Error != nil {
		return nil, apperror.Internal("failed to begin transaction", tx.Error)
	}
	return tx, nil
}

// Commit commits a transaction.
// All changes made within the transaction become permanent.
func (t *TransactionManager) Commit(tx *gorm.DB) error {
	if err := tx.Commit().Error; err != nil {
		return apperror.Internal("failed to commit transaction", err)
	}
	return nil
}

// Rollback rolls back a transaction.
// All changes made within the transaction are discarded.
func (t *TransactionManager) Rollback(tx *gorm.DB) error {
	if err := tx.Rollback().Error; err != nil {
		return apperror.Internal("failed to rollback transaction", err)
	}
	return nil
}

// WithTransaction executes a function within a transaction.
// Automatically commits on success or rolls back on error/panic.
//
// Example usage:
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

	// Ensure rollback on panic
	defer func() {
		if r := recover(); r != nil {
			tx.Rollback()
			panic(r) // Re-throw panic
		}
	}()

	// Execute the function
	if err := fn(tx); err != nil {
		if rbErr := tx.Rollback().Error; rbErr != nil {
			return apperror.Internal("failed to rollback transaction", rbErr)
		}
		return err
	}

	// Commit the transaction
	if err := tx.Commit().Error; err != nil {
		return apperror.Internal("failed to commit transaction", err)
	}
	return nil
}

// DB returns the underlying database connection.
// Use this when you need direct access to the database outside of transactions.
func (t *TransactionManager) DB() *gorm.DB {
	return t.db
}
