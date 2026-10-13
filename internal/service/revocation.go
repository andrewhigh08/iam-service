package service

import (
	"context"
	"time"

	"github.com/andrewhigh08/iam-service/internal/port"
)

// revocationGrace extends a revocation record beyond the access token TTL so that it outlives
// every token it invalidates.
const revocationGrace = time.Minute

// accessRevoker ends the sessions of a user and invalidates the access tokens issued so far.
type accessRevoker struct {
	sessions    port.SessionStore
	revocations port.RevocationStore
	accessTTL   time.Duration
}

// revokeAll records now as the revocation instant of the user and then deletes every session
// of the user, in that order: a session that survives the deletion was opened after the
// instant was recorded, so its tokens are never older than the instant. It returns the number
// of sessions removed.
func (r accessRevoker) revokeAll(ctx context.Context, userID int64, now time.Time) (int, error) {
	keep := r.accessTTL + revocationGrace
	if err := r.revocations.RevokeUserTokensBefore(ctx, userID, now, keep); err != nil {
		return 0, asInternal("failed to revoke access tokens", err)
	}
	removed, err := r.sessions.DeleteAllForUser(ctx, userID)
	if err != nil {
		return 0, asInternal("failed to delete sessions", err)
	}
	return removed, nil
}
