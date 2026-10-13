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

// revokeAll deletes every session of the user and then records now as the revocation
// instant, so that any session live afterwards is known to have been opened after it. It
// returns the number of sessions removed.
func (r accessRevoker) revokeAll(ctx context.Context, userID int64, now time.Time) (int, error) {
	removed, err := r.sessions.DeleteAllForUser(ctx, userID)
	if err != nil {
		return 0, asInternal("failed to delete sessions", err)
	}
	keep := r.accessTTL + revocationGrace
	if err := r.revocations.RevokeUserTokensBefore(ctx, userID, now, keep); err != nil {
		return removed, asInternal("failed to revoke access tokens", err)
	}
	return removed, nil
}
