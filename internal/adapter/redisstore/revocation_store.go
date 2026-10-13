package redisstore

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// revokeBeforeScript records the revocation instant ARGV[1] unless a later one is already
// stored, so that a replica with a lagging clock can never move the instant backwards. The
// TTL is refreshed to ARGV[2] either way. It returns 1 when the value was written.
var revokeBeforeScript = redis.NewScript(`
local current = redis.call('GET', KEYS[1])
if current and tonumber(current) >= tonumber(ARGV[1]) then
	redis.call('PEXPIRE', KEYS[1], ARGV[2])
	return 0
end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
return 1
`)

// RevocationStore implements port.RevocationStore on Redis string keys with TTLs.
type RevocationStore struct {
	client redis.Cmdable
}

// NewRevocationStore returns a RevocationStore using client.
func NewRevocationStore(client redis.Cmdable) *RevocationStore {
	return &RevocationStore{client: client}
}

// RevokeToken blacklists jti for ttl. A non-positive ttl means the token has already expired,
// so nothing is stored.
func (s *RevocationStore) RevokeToken(ctx context.Context, jti string, ttl time.Duration) error {
	if ttl <= 0 {
		return nil
	}
	if err := s.client.Set(ctx, revokedJTIKey(jti), "1", ttl).Err(); err != nil {
		return apperror.Internal("failed to revoke token", err)
	}
	return nil
}

// IsTokenRevoked reports whether jti is blacklisted.
func (s *RevocationStore) IsTokenRevoked(ctx context.Context, jti string) (bool, error) {
	n, err := s.client.Exists(ctx, revokedJTIKey(jti)).Result()
	if err != nil {
		return false, apperror.Internal("failed to check token revocation", err)
	}
	return n > 0, nil
}

// RevokeUserTokensBefore records t, truncated to whole seconds, as the instant before which
// every access token of the user is invalid. The record is kept for keep. An instant earlier
// than the one already stored is ignored, so the recorded instant only ever moves forward.
func (s *RevocationStore) RevokeUserTokensBefore(ctx context.Context, userID int64, t time.Time, keep time.Duration) error {
	if keep <= 0 {
		return apperror.Internal("failed to revoke user tokens", errNonPositiveTTL)
	}
	keys := []string{userRevokedBeforeKey(userID)}
	err := revokeBeforeScript.Run(ctx, s.client, keys, t.Unix(), max(keep.Milliseconds(), 1)).Err()
	if err != nil {
		return apperror.Internal("failed to revoke user tokens", err)
	}
	return nil
}

// UserTokensRevokedBefore returns the recorded instant, or the zero time when none is recorded.
func (s *RevocationStore) UserTokensRevokedBefore(ctx context.Context, userID int64) (time.Time, error) {
	sec, err := s.client.Get(ctx, userRevokedBeforeKey(userID)).Int64()
	if errors.Is(err, redis.Nil) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, apperror.Internal("failed to load user revocation instant", err)
	}
	return time.Unix(sec, 0).UTC(), nil
}
