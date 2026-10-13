package port

import (
	"context"
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// SessionStore keeps refresh-token sessions keyed by the SHA-256 hex digest of the refresh token.
type SessionStore interface {
	// Create stores s under s.TokenHash for ttl. The caller derives s.ID (the sid carried by
	// access tokens) as hex(sha256(token))[:domain.SessionIDLength].
	Create(ctx context.Context, s domain.Session, ttl time.Duration) error
	// Get returns the session stored under tokenHash or apperror.NotFound.
	Get(ctx context.Context, tokenHash string) (*domain.Session, error)
	// Take removes the session stored under tokenHash and returns it in one atomic step, so a
	// refresh token presented concurrently yields exactly one session. The hash is remembered as
	// consumed for keep. Returns apperror.NotFound when there is no such session.
	Take(ctx context.Context, tokenHash string, keep time.Duration) (*domain.Session, error)
	// ConsumedBy returns the id of the user whose session Take removed under tokenHash, or 0
	// when the hash is unknown or the record has expired.
	ConsumedBy(ctx context.Context, tokenHash string) (int64, error)
	// Delete removes the session stored under tokenHash. Deleting a missing session is not an error.
	Delete(ctx context.Context, tokenHash string) error
	// DeleteAllForUser removes every session of the user and returns how many were removed.
	DeleteAllForUser(ctx context.Context, userID int64) (int, error)
	// ListForUser returns the live sessions of the user; expired entries are pruned on read.
	ListForUser(ctx context.Context, userID int64) ([]domain.Session, error)
}
