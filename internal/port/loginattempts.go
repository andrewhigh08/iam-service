package port

import (
	"context"
	"time"
)

// LoginAttemptStore counts failed logins per key (the normalised email) and holds temporary locks.
type LoginAttemptStore interface {
	// RecordFailure increments the failure counter for key and returns the new count.
	// The counter expires after window, measured from its creation.
	RecordFailure(ctx context.Context, key string, window time.Duration) (int64, error)
	// Lock marks key as locked for d.
	Lock(ctx context.Context, key string, d time.Duration) error
	// IsLocked reports whether key is currently locked.
	IsLocked(ctx context.Context, key string) (bool, error)
	// Reset clears the failure counter and the lock for key.
	Reset(ctx context.Context, key string) error
}
