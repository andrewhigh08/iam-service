package service

import (
	"context"
	"slices"
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// Refresh rotates the session of refreshToken: the old session is consumed atomically and a
// new pair is issued whose session keeps the original start time. A token whose session was
// already rotated is a replay: every session of its user is revoked.
func (s *AuthService) Refresh(ctx context.Context, refreshToken string, meta domain.ClientMeta) (*port.TokenPair, error) {
	if refreshToken == "" {
		return nil, apperror.Unauthorized(msgRefreshRejected)
	}
	tokenHash := hashToken(refreshToken)
	session, err := s.deps.Sessions.Take(ctx, tokenHash, s.cfg.RefreshTTL)
	if isNotFound(err) {
		return nil, s.rejectUnknownRefresh(ctx, tokenHash, meta)
	}
	if err != nil {
		return nil, asInternal(msgLoadSessionFailed, err)
	}
	user, err := s.refreshableUser(ctx, session)
	if err != nil {
		return nil, err
	}
	if revokeErr := s.revokeSessionAccessToken(ctx, session); revokeErr != nil {
		// The previous access token expires on its own; losing the blacklist entry does not
		// justify ending the session that was just rotated.
		s.logger.FromContext(ctx).Warn("failed to revoke the previous access token", "error", revokeErr)
	}
	issued, err := s.issueTokens(ctx, user, meta, session.CreatedAt)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, user.ID, domain.AuditActionTokenRefresh, formatID(user.ID), meta, map[string]any{
		"previous_sid": session.ID,
		"sid":          issued.sid,
	})
	s.logger.FromContext(ctx).Info("session rotated", "user_id", user.ID, "sid", issued.sid)
	return issued.tokens, nil
}

// refreshableUser loads the owner of session and checks that the session may be rotated: the
// account exists and is not blocked, the password has neither been replaced nor flagged for a
// change since the session started, and the session is younger than its maximum age. The
// session was already consumed, so a rejection ends it.
func (s *AuthService) refreshableUser(ctx context.Context, session *domain.Session) (*domain.User, error) {
	user, err := s.deps.Users.FindByID(ctx, session.UserID)
	switch {
	case isNotFound(err):
		return nil, apperror.Unauthorized(msgRefreshRejected)
	case err != nil:
		return nil, asInternal(msgLoadUserFailed, err)
	case user.IsBlocked:
		return nil, apperror.Unauthorized(msgAccountBlocked)
	case s.passwordChangeReason(user) != "":
		return nil, apperror.Unauthorized(msgPasswordChangeRequired)
	}
	log := s.logger.FromContext(ctx)
	switch {
	case startedBefore(session, user.PasswordChangedAt):
		log.Info("refresh rejected: password changed after the session started", "user_id", user.ID, "sid", session.ID)
		return nil, apperror.Unauthorized(msgRefreshRejected)
	case s.cfg.SessionMaxAge > 0 && s.now().Sub(session.CreatedAt) >= s.cfg.SessionMaxAge:
		log.Info("refresh rejected: session reached its maximum age", "user_id", user.ID, "sid", session.ID)
		return nil, apperror.Unauthorized(msgRefreshRejected)
	}
	return user, nil
}

// startedBefore reports whether session began before instant. Stored session times have second
// resolution, so the comparison is made at that resolution.
func startedBefore(session *domain.Session, instant time.Time) bool {
	return session.CreatedAt.Truncate(time.Second).Before(instant.Truncate(time.Second))
}

// rejectUnknownRefresh answers a refresh token that has no session. When the token was consumed
// by an earlier rotation, someone is replaying it while another party holds its successor, so
// every session of the user is ended and the event is audited.
func (s *AuthService) rejectUnknownRefresh(ctx context.Context, tokenHash string, meta domain.ClientMeta) error {
	userID, err := s.deps.Sessions.ConsumedBy(ctx, tokenHash)
	if err != nil {
		return asInternal(msgLoadSessionFailed, err)
	}
	if userID == 0 {
		return apperror.Unauthorized(msgRefreshRejected)
	}
	removed, err := s.revoker.revokeAll(ctx, userID, s.now())
	if err != nil {
		return err
	}
	s.audit(ctx, userID, domain.AuditActionTokenReuse, formatID(userID), meta, map[string]any{
		"sid":              sessionID(tokenHash),
		"sessions_revoked": removed,
	})
	s.logger.FromContext(ctx).Warn("refresh token reuse detected, all sessions revoked", "user_id", userID, "sessions", removed)
	return apperror.Unauthorized(msgRefreshRejected)
}

// revokeSessionAccessToken blacklists the access token issued with session for as long as the
// parser still accepts it. A session that recorded no token, or whose token is past that
// point, needs nothing.
func (s *AuthService) revokeSessionAccessToken(ctx context.Context, session *domain.Session) error {
	if session == nil || session.AccessJTI == "" {
		return nil
	}
	remaining := s.blacklistTTL(session.AccessExpiresAt)
	if remaining <= 0 {
		return nil
	}
	if err := s.deps.Revocations.RevokeToken(ctx, session.AccessJTI, remaining); err != nil {
		return asInternal(msgRevokeTokenFailed, err)
	}
	return nil
}

// blacklistTTL returns how long a token expiring at exp must stay blacklisted: the parser
// accepts it until exp plus the clock-skew leeway, so the entry has to live that long.
func (s *AuthService) blacklistTTL(exp time.Time) time.Duration {
	return exp.Sub(s.now()) + clockSkewLeeway
}

// Logout ends the session of refreshToken and blacklists its access token, as well as
// accessToken when one is supplied and still valid. A session that no longer exists is not an
// error, but a blacklist that cannot be written is.
func (s *AuthService) Logout(ctx context.Context, refreshToken, accessToken string, meta domain.ClientMeta) error {
	var actorID int64
	details := map[string]any{}
	if refreshToken != "" {
		session, err := s.endSession(ctx, hashToken(refreshToken))
		if err != nil {
			return err
		}
		if session != nil {
			actorID = session.UserID
			details["sid"] = session.ID
		}
	}
	if accessToken != "" {
		claims, revoked, err := s.revokeAccessToken(ctx, accessToken)
		if err != nil {
			return err
		}
		if claims != nil {
			details["access_token_revoked"] = revoked
			if actorID == 0 {
				actorID = claims.UserID
			}
		}
	}
	if actorID == 0 {
		return nil
	}
	s.audit(ctx, actorID, domain.AuditActionLogout, formatID(actorID), meta, details)
	s.logger.FromContext(ctx).Info("logout", "user_id", actorID)
	return nil
}

// endSession deletes the session stored under tokenHash, blacklists the access token it
// recorded and returns it, or nil when it had already expired or been revoked.
func (s *AuthService) endSession(ctx context.Context, tokenHash string) (*domain.Session, error) {
	session, err := s.deps.Sessions.Get(ctx, tokenHash)
	switch {
	case isNotFound(err):
		session = nil
	case err != nil:
		return nil, asInternal(msgLoadSessionFailed, err)
	}
	if delErr := s.deps.Sessions.Delete(ctx, tokenHash); delErr != nil {
		return nil, asInternal(msgDeleteSessionFailed, delErr)
	}
	if err := s.revokeSessionAccessToken(ctx, session); err != nil {
		return nil, err
	}
	return session, nil
}

// revokeAccessToken blacklists the jti of an access token the parser accepts for as long as
// it keeps accepting it. It returns the claims when the token could be parsed and whether it
// was blacklisted; a token that does not parse is ignored, a blacklist that cannot be written
// is an error.
func (s *AuthService) revokeAccessToken(ctx context.Context, accessToken string) (*port.Claims, bool, error) {
	claims, err := s.parseAccessToken(accessToken)
	if err != nil {
		s.logger.FromContext(ctx).Debug("access token not revoked at logout", "error", err)
		return nil, false, nil
	}
	remaining := s.blacklistTTL(claims.ExpiresAt.Time)
	if remaining <= 0 {
		return claims, false, nil
	}
	if revokeErr := s.deps.Revocations.RevokeToken(ctx, claims.ID, remaining); revokeErr != nil {
		return claims, false, asInternal(msgRevokeTokenFailed, revokeErr)
	}
	return claims, true, nil
}

// LogoutAll ends every session of the user and invalidates the access tokens issued so far.
func (s *AuthService) LogoutAll(ctx context.Context, userID int64, meta domain.ClientMeta) error {
	removed, err := s.revoker.revokeAll(ctx, userID, s.now())
	if err != nil {
		return err
	}
	s.audit(ctx, userID, domain.AuditActionLogoutAll, formatID(userID), meta, map[string]any{
		"sessions_revoked": removed,
	})
	s.logger.FromContext(ctx).Info("all sessions revoked", "user_id", userID, "sessions", removed)
	return nil
}

// ListSessions returns the live sessions of the user in the order the store keeps them,
// newest first, flagging the one whose sid is currentSID.
func (s *AuthService) ListSessions(ctx context.Context, userID int64, currentSID string) ([]domain.Session, error) {
	sessions, err := s.deps.Sessions.ListForUser(ctx, userID)
	if err != nil {
		return nil, asInternal(msgListSessionsFailed, err)
	}
	for i := range sessions {
		sessions[i].Current = currentSID != "" && sessions[i].ID == currentSID
	}
	return sessions, nil
}

// RevokeSession ends the session sid of the user and blacklists the access token issued with
// it. Sessions of other users are reported as not found.
func (s *AuthService) RevokeSession(ctx context.Context, userID int64, sid string, meta domain.ClientMeta) error {
	sessions, err := s.deps.Sessions.ListForUser(ctx, userID)
	if err != nil {
		return asInternal(msgListSessionsFailed, err)
	}
	idx := slices.IndexFunc(sessions, func(sess domain.Session) bool { return sess.ID == sid })
	if sid == "" || idx < 0 {
		return apperror.NotFound("session", sid)
	}
	session := &sessions[idx]
	if session.TokenHash == "" {
		return apperror.Internal("session has no token hash", nil)
	}
	if delErr := s.deps.Sessions.Delete(ctx, session.TokenHash); delErr != nil {
		return asInternal(msgDeleteSessionFailed, delErr)
	}
	if err := s.revokeSessionAccessToken(ctx, session); err != nil {
		return err
	}
	s.audit(ctx, userID, domain.AuditActionSessionRevoke, formatID(userID), meta, map[string]any{"sid": sid})
	s.logger.FromContext(ctx).Info("session revoked", "user_id", userID, "sid", sid)
	return nil
}
