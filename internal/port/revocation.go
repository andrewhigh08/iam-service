package port

import (
	"context"
	"time"
)

// RevocationStore records revoked access tokens and per-user revocation instants.
type RevocationStore interface {
	// RevokeToken blacklists the access token identified by jti for ttl, its remaining lifetime.
	RevokeToken(ctx context.Context, jti string, ttl time.Duration) error
	// IsTokenRevoked reports whether jti has been blacklisted.
	IsTokenRevoked(ctx context.Context, jti string) (bool, error)
	// RevokeUserTokensBefore records that every access token of the user issued before t is
	// invalid. The record is kept for keep, the maximum access token TTL, so it expires on its own.
	RevokeUserTokensBefore(ctx context.Context, userID int64, t time.Time, keep time.Duration) error
	// UserTokensRevokedBefore returns the recorded instant, or the zero time when none is recorded.
	UserTokensRevokedBefore(ctx context.Context, userID int64) (time.Time, error)
	// Check answers IsTokenRevoked for jti and UserTokensRevokedBefore for userID in a single
	// round trip, which is what validating an access token needs.
	Check(ctx context.Context, jti string, userID int64) (tokenRevoked bool, revokedBefore time.Time, err error)
}
