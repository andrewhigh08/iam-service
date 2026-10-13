package port

import "context"

// TxManager runs a function inside a database transaction.
type TxManager interface {
	// WithinTx runs fn inside a transaction carried in ctx; repositories obtain it through
	// their adapter-local helper. Nested calls reuse the outer transaction.
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}
