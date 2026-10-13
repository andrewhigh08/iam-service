package service

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

func TestAuthService_Logout_EndsSessionAndRevokesAccessTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	refresh, hash, session := refreshFixture(user, f.now, 'c')
	access := f.issuedToken(user, session.ID)
	claims := f.parseClaims(access)
	gomock.InOrder(
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil),
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil),
		f.revocations.EXPECT().RevokeToken(gomock.Any(), session.AccessJTI, 10*time.Minute+clockSkewLeeway).Return(nil),
		f.revocations.EXPECT().RevokeToken(gomock.Any(), claims.ID, testAccessTTL+clockSkewLeeway).Return(nil),
	)
	event := expectAudit(f.audit, domain.AuditActionLogout)

	require.NoError(t, f.svc.Logout(t.Context(), refresh, access, f.meta))

	assert.Equal(t, user.ID, event.ActorID)
	assert.Equal(t, "42", event.ResourceID)
	assert.Equal(t, f.meta, event.ClientMeta)
	assert.Equal(t, map[string]any{"sid": session.ID, "access_token_revoked": true}, event.Details)
}

func TestAuthService_Logout_Variants(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	t.Run("nothing to do", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)

		require.NoError(t, f.svc.Logout(t.Context(), "", "", f.meta))
	})
	t.Run("unknown refresh token is deleted anyway and not audited", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, _ := refreshFixture(f.user(), f.now, 'd')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(nil, apperror.NotFound("session", hash))
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, "", f.meta))
	})
	t.Run("session without a recorded access token", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, session := refreshFixture(f.user(), f.now, 'n')
		session.AccessJTI = ""
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, "", f.meta))
	})
	t.Run("session whose access token expired within the leeway is blacklisted for the rest of it", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, session := refreshFixture(f.user(), f.now, 'o')
		session.AccessExpiresAt = f.now.Add(-10 * time.Second)
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), session.AccessJTI, clockSkewLeeway-10*time.Second).Return(nil)
		expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, "", f.meta))
	})
	t.Run("session whose access token is past the leeway", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, session := refreshFixture(f.user(), f.now, 'q')
		session.AccessExpiresAt = f.now.Add(-clockSkewLeeway)
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, "", f.meta))
	})
	t.Run("access token alone identifies the actor", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		access := f.issuedToken(user, testSID)
		claims := f.parseClaims(access)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), claims.ID, testAccessTTL+clockSkewLeeway).Return(nil)
		event := expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), "", access, f.meta))

		assert.Equal(t, user.ID, event.ActorID)
		assert.Equal(t, map[string]any{"access_token_revoked": true}, event.Details)
	})
	t.Run("invalid access token is ignored", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		refresh, hash, session := refreshFixture(user, f.now, 'e')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), session.AccessJTI, gomock.Any()).Return(nil)
		event := expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, "garbage", f.meta))

		assert.Equal(t, map[string]any{"sid": session.ID}, event.Details)
	})
	t.Run("expired access token is ignored", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		expired, _, err := f.svc.signAccessToken(user, nil, testSID, f.now.Add(-time.Hour))
		require.NoError(t, err)
		refresh, hash, session := refreshFixture(user, f.now, 'f')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), session.AccessJTI, gomock.Any()).Return(nil)
		event := expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), refresh, expired, f.meta))

		assert.Equal(t, map[string]any{"sid": session.ID}, event.Details)
	})
	t.Run("access token that expired within the leeway is blacklisted for the rest of it", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		// exp is 10s in the past: the parser accepts the token for another 20s, so the
		// blacklist entry has to live that long.
		access, jti, err := f.svc.signAccessToken(user, nil, testSID, f.now.Add(-testAccessTTL-10*time.Second))
		require.NoError(t, err)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), jti, clockSkewLeeway-10*time.Second).Return(nil)
		event := expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), "", access, f.meta))

		assert.Equal(t, user.ID, event.ActorID)
		assert.Equal(t, map[string]any{"access_token_revoked": true}, event.Details)
	})
	t.Run("access token past the leeway is not blacklisted", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		access := f.issuedToken(user, testSID)
		f.now = f.now.Add(testAccessTTL + clockSkewLeeway)
		event := expectAudit(f.audit, domain.AuditActionLogout)

		require.NoError(t, f.svc.Logout(t.Context(), "", access, f.meta))

		assert.Equal(t, user.ID, event.ActorID)
		assert.Equal(t, map[string]any{"access_token_revoked": false}, event.Details)
	})
	t.Run("blacklist failure fails the logout", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		access := f.issuedToken(f.user(), testSID)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), gomock.Any(), testAccessTTL+clockSkewLeeway).Return(boom)

		err := f.svc.Logout(t.Context(), "", access, f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgRevokeTokenFailed, appErr.Message)
		require.ErrorIs(t, err, boom)
	})
	t.Run("session token blacklist failure fails the logout", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, session := refreshFixture(f.user(), f.now, 'p')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(nil)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), session.AccessJTI, gomock.Any()).Return(boom)

		err := f.svc.Logout(t.Context(), refresh, "", f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgRevokeTokenFailed, appErr.Message)
	})
	t.Run("session lookup failure", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, _ := refreshFixture(f.user(), f.now, 'g')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(nil, boom)

		err := f.svc.Logout(t.Context(), refresh, "", f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgLoadSessionFailed, appErr.Message)
	})
	t.Run("session deletion failure", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		refresh, hash, session := refreshFixture(f.user(), f.now, 'h')
		f.sessions.EXPECT().Get(gomock.Any(), hash).Return(session, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), hash).Return(boom)

		err := f.svc.Logout(t.Context(), refresh, "", f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgDeleteSessionFailed, appErr.Message)
	})
}

func TestAuthService_LogoutAll_RevokesSessionsAndTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	gomock.InOrder(
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), testUserID, f.now, testAccessTTL+revocationGrace).Return(nil),
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), testUserID).Return(2, nil),
	)
	event := expectAudit(f.audit, domain.AuditActionLogoutAll)

	require.NoError(t, f.svc.LogoutAll(t.Context(), testUserID, f.meta))

	assert.Equal(t, testUserID, event.ActorID)
	assert.Equal(t, "42", event.ResourceID)
	assert.Equal(t, f.meta, event.ClientMeta)
	assert.Equal(t, map[string]any{"sessions_revoked": 2}, event.Details)
}

func TestAuthService_LogoutAll_StoreFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	t.Run("revocation failure stops before the session wipe", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), testUserID, f.now, testAccessTTL+revocationGrace).Return(boom)

		err := f.svc.LogoutAll(t.Context(), testUserID, f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to revoke access tokens", appErr.Message)
		require.ErrorIs(t, err, boom)
	})
	t.Run("session wipe failure after the instant was recorded", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), testUserID, f.now, testAccessTTL+revocationGrace).Return(nil)
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), testUserID).Return(0, boom)

		err := f.svc.LogoutAll(t.Context(), testUserID, f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to delete sessions", appErr.Message)
	})
}

func TestAuthService_ListSessions(t *testing.T) {
	t.Parallel()
	t.Run("marks the current session and keeps the store's order", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		// The store owns the ordering, so an order the service would change if it sorted
		// must come back untouched.
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{
			{ID: "older", CreatedAt: f.now.Add(-3 * time.Hour)},
			{ID: "newest", CreatedAt: f.now.Add(-time.Minute)},
			{ID: "middle", CreatedAt: f.now.Add(-time.Hour)},
		}, nil)

		got, err := f.svc.ListSessions(t.Context(), testUserID, "middle")

		require.NoError(t, err)
		require.Len(t, got, 3)
		ids := make([]string, 0, len(got))
		current := make([]bool, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
			current = append(current, s.Current)
		}
		assert.Equal(t, []string{"older", "newest", "middle"}, ids)
		assert.Equal(t, []bool{false, false, true}, current)
	})
	t.Run("marks nothing without a current sid", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{{ID: "only"}}, nil)

		got, err := f.svc.ListSessions(t.Context(), testUserID, "")

		require.NoError(t, err)
		require.Len(t, got, 1)
		assert.False(t, got[0].Current)
	})
	t.Run("store failure is internal", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return(nil, errors.New("redis down"))

		got, err := f.svc.ListSessions(t.Context(), testUserID, "")

		assert.Nil(t, got)
		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgListSessionsFailed, appErr.Message)
	})
}

func TestAuthService_RevokeSession(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	own := domain.Session{ID: "ownsid0000000000", TokenHash: "digest-of-own-token", UserID: testUserID}
	t.Run("own session is deleted and audited", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{own}, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), own.TokenHash).Return(nil)
		event := expectAudit(f.audit, domain.AuditActionSessionRevoke)

		require.NoError(t, f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta))

		assert.Equal(t, testUserID, event.ActorID)
		assert.Equal(t, f.meta, event.ClientMeta)
		assert.Equal(t, map[string]any{"sid": own.ID}, event.Details)
	})
	t.Run("the session's access token is blacklisted for its remaining life", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		withToken := own
		withToken.AccessJTI = "jti-of-own-session"
		withToken.AccessExpiresAt = f.now.Add(7 * time.Minute)
		gomock.InOrder(
			f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{withToken}, nil),
			f.sessions.EXPECT().Delete(gomock.Any(), own.TokenHash).Return(nil),
			f.revocations.EXPECT().RevokeToken(gomock.Any(), "jti-of-own-session", 7*time.Minute+clockSkewLeeway).Return(nil),
		)
		expectAudit(f.audit, domain.AuditActionSessionRevoke)

		require.NoError(t, f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta))
	})
	t.Run("a blacklist failure is reported", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		withToken := own
		withToken.AccessJTI = "jti-of-own-session"
		withToken.AccessExpiresAt = f.now.Add(7 * time.Minute)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{withToken}, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), own.TokenHash).Return(nil)
		f.revocations.EXPECT().RevokeToken(gomock.Any(), "jti-of-own-session", 7*time.Minute+clockSkewLeeway).Return(boom)

		err := f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, msgRevokeTokenFailed, appErr.Message)
	})
	t.Run("another user's session is not found", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{own}, nil)

		err := f.svc.RevokeSession(t.Context(), testUserID, "foreignsid000000", f.meta)

		appErr := requireAppError(t, err, apperror.CodeNotFound)
		assert.Equal(t, "foreignsid000000", appErr.Details["id"])
	})
	t.Run("empty sid is not found", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{own}, nil)

		requireAppError(t, f.svc.RevokeSession(t.Context(), testUserID, "", f.meta), apperror.CodeNotFound)
	})
	t.Run("session without a token hash cannot be deleted", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{{ID: own.ID, UserID: testUserID}}, nil)

		requireAppError(t, f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta), apperror.CodeInternal)
	})
	t.Run("store failures are internal", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return(nil, boom)
		requireAppError(t, f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta), apperror.CodeInternal)

		f.sessions.EXPECT().ListForUser(gomock.Any(), testUserID).Return([]domain.Session{own}, nil)
		f.sessions.EXPECT().Delete(gomock.Any(), own.TokenHash).Return(boom)
		requireAppError(t, f.svc.RevokeSession(t.Context(), testUserID, own.ID, f.meta), apperror.CodeInternal)
	})
}
