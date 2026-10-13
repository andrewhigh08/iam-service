package postgres

import (
	"context"

	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// txKey is the context key under which an open transaction travels.
type txKey struct{}

// TxManager implements port.TxManager with GORM transactions carried in the context.
type TxManager struct {
	db *gorm.DB
}

// NewTxManager returns a TxManager that opens transactions on db.
func NewTxManager(db *gorm.DB) *TxManager {
	return &TxManager{db: db}
}

// WithinTx runs fn with a context that carries a transaction. When ctx already carries one,
// fn joins it. Otherwise a new transaction is rolled back when fn returns an error or panics
// and committed when it returns nil.
func (m *TxManager) WithinTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := txFromCtx(ctx); ok {
		return fn(ctx)
	}

	var fnErr error
	err := m.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		fnErr = fn(context.WithValue(ctx, txKey{}, tx))
		return fnErr
	})
	if fnErr != nil {
		return fnErr
	}
	if err != nil {
		return apperror.Internal("transaction failed", err)
	}
	return nil
}

// WithinLockedTx is WithinTx with the transaction-scoped advisory lock key taken first, so
// that callers across replicas run fn one at a time. The lock is released with the transaction.
func (m *TxManager) WithinLockedTx(ctx context.Context, key int64, fn func(ctx context.Context) error) error {
	return m.WithinTx(ctx, func(ctx context.Context) error {
		err := dbFromCtx(ctx, m.db).WithContext(ctx).Exec("SELECT pg_advisory_xact_lock(?)", key).Error
		if err != nil {
			return apperror.Internal("failed to acquire advisory lock", err)
		}
		return fn(ctx)
	})
}

// txFromCtx returns the transaction carried in ctx, if any.
func txFromCtx(ctx context.Context) (*gorm.DB, bool) {
	tx, ok := ctx.Value(txKey{}).(*gorm.DB)
	return tx, ok && tx != nil
}

// dbFromCtx returns the transaction carried in ctx, or fallback when there is none.
func dbFromCtx(ctx context.Context, fallback *gorm.DB) *gorm.DB {
	if tx, ok := txFromCtx(ctx); ok {
		return tx
	}
	return fallback
}

// repo is the shared base of every repository in this package.
type repo struct {
	db *gorm.DB
}

// conn returns the handle to run queries for ctx on: its transaction, or the connection pool.
func (r repo) conn(ctx context.Context) *gorm.DB {
	return dbFromCtx(ctx, r.db).WithContext(ctx)
}
