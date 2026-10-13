package redisstore

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// recordFailureScript increments the counter and sets its TTL only when the key was created,
// so the window is measured from the first failure.
var recordFailureScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
return count
`)

// LoginAttemptStore implements port.LoginAttemptStore on Redis counters and lock keys.
type LoginAttemptStore struct {
	client redis.Cmdable
}

// NewLoginAttemptStore returns a LoginAttemptStore using client.
func NewLoginAttemptStore(client redis.Cmdable) *LoginAttemptStore {
	return &LoginAttemptStore{client: client}
}

// RecordFailure increments the failure counter of key and returns the new count.
// The counter expires window after its creation.
func (s *LoginAttemptStore) RecordFailure(ctx context.Context, key string, window time.Duration) (int64, error) {
	if window <= 0 {
		return 0, apperror.Internal("failed to record login failure", errNonPositiveTTL)
	}
	windowMillis := max(window.Milliseconds(), 1)
	count, err := recordFailureScript.Run(ctx, s.client, []string{loginFailKey(key)}, windowMillis).Int64()
	if err != nil {
		return 0, apperror.Internal("failed to record login failure", err)
	}
	return count, nil
}

// Lock marks key as locked for d.
func (s *LoginAttemptStore) Lock(ctx context.Context, key string, d time.Duration) error {
	if d <= 0 {
		return apperror.Internal("failed to lock login", errNonPositiveTTL)
	}
	if err := s.client.Set(ctx, loginLockKey(key), "1", d).Err(); err != nil {
		return apperror.Internal("failed to lock login", err)
	}
	return nil
}

// IsLocked reports whether key is locked.
func (s *LoginAttemptStore) IsLocked(ctx context.Context, key string) (bool, error) {
	n, err := s.client.Exists(ctx, loginLockKey(key)).Result()
	if err != nil {
		return false, apperror.Internal("failed to check login lock", err)
	}
	return n > 0, nil
}

// Reset clears the failure counter and the lock of key.
func (s *LoginAttemptStore) Reset(ctx context.Context, key string) error {
	if err := s.client.Del(ctx, loginFailKey(key), loginLockKey(key)).Err(); err != nil {
		return apperror.Internal("failed to reset login attempts", err)
	}
	return nil
}
