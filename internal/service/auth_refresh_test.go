package service

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// refreshFixture returns a refresh token, its digest and the live session stored under it:
// one started after the user's last password change, carrying an unexpired access token.
func refreshFixture(user *domain.User, now time.Time, fill byte) (token, hash string, session *domain.Session) {
	token = strings.Repeat(string(fill), 2*refreshTokenBytes)
	hash = hashToken(token)
	session = &domain.Session{
		ID:              sessionID(hash),
		TokenHash:       hash,
		UserID:          user.ID,
		CreatedAt:       now.Add(-30 * time.Minute),
		ExpiresAt:       now.Add(time.Hour),
		IP:              "198.51.100.1",
		UserAgent:       "old-agent/0.1",
		AccessJTI:       "previous-jti-" + string(fill),
		AccessExpiresAt: now.Add(10 * time.Minute),
	}
	return token, hash, session
}

func TestAuthService_Refresh_RotatesSession(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	oldToken, oldHash, current := refreshFixture(user, f.now, 'a')
	stored, create := f.expectSessionCreate()
	gomock.InOrder(
		f.sessions.EXPECT().Take(gomock.Any(), oldHash, testRefreshTTL).Return(current, nil),
		f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil),
		f.revocations.EXPECT().RevokeToken(gomock.Any(), current.AccessJTI, 10*time.Minute).Return(nil),
		f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return([]string{domain.RoleAnalyst}, nil),
		create,
	)
	event := expectAudit(f.audit, domain.AuditActionTokenRefresh)

	pair, err := f.svc.Refresh(t.Context(), oldToken, f.meta)

	require.NoError(t, err)
	assert.NotEqual(t, oldToken, pair.RefreshToken)
	assert.Equal(t, hashToken(pair.RefreshToken), stored.TokenHash)
	assert.NotEqual(t, current.ID, stored.ID, "a new token means a new sid")
	assert.Equal(t, current.CreatedAt, stored.CreatedAt, "the session start survives the rotation")
	assert.Equal(t, f.now.Add(testRefreshTTL), stored.ExpiresAt)
	assert.Equal(t, f.meta.IP, stored.IP)
	assert.Equal(t, f.meta.UserAgent, stored.UserAgent)
	claims := f.parseClaims(pair.AccessToken)
	assert.Equal(t, stored.ID, claims.SessionID)
	assert.Equal(t, []string{domain.RoleAnalyst}, claims.Roles)
	assert.Equal(t, claims.ID, stored.AccessJTI, "the new session records its access token")
	assert.Equal(t, user.ID, event.ActorID)
	assert.Equal(t, map[string]any{"previous_sid": current.ID, "sid": stored.ID}, event.Details)
}

func TestAuthService_Refresh_ToleratesPreviousTokenBlacklistFailure(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	oldToken, oldHash, current := refreshFixture(user, f.now, 'z')
	f.sessions.EXPECT().Take(gomock.Any(), oldHash, testRefreshTTL).Return(current, nil)
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.revocations.EXPECT().RevokeToken(gomock.Any(), current.AccessJTI, gomock.Any()).Return(errors.New("redis down"))
	f.expectIssue(user, nil)
	expectAudit(f.audit, domain.AuditActionTokenRefresh)

	pair, err := f.svc.Refresh(t.Context(), oldToken, f.meta)

	require.NoError(t, err)
	assert.NotNil(t, pair)
}

func TestAuthService_Refresh_CapsSessionLifetimeAtMaxAge(t *testing.T) {
	t.Parallel()
	const maxAge = 2 * time.Hour
	f := newAuthFixture(t, func(c *AuthConfig) { c.SessionMaxAge = maxAge })
	user := f.user()
	oldToken, oldHash, current := refreshFixture(user, f.now, 'm')
	f.sessions.EXPECT().Take(gomock.Any(), oldHash, testRefreshTTL).Return(current, nil)
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.revocations.EXPECT().RevokeToken(gomock.Any(), current.AccessJTI, gomock.Any()).Return(nil)
	f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return(nil, nil)
	stored := &domain.Session{}
	remaining := current.CreatedAt.Add(maxAge).Sub(f.now)
	f.sessions.EXPECT().Create(gomock.Any(), gomock.Any(), remaining).DoAndReturn(func(_ any, s domain.Session, _ time.Duration) error {
		*stored = s
		return nil
	})
	expectAudit(f.audit, domain.AuditActionTokenRefresh)

	_, err := f.svc.Refresh(t.Context(), oldToken, f.meta)

	require.NoError(t, err)
	assert.Equal(t, current.CreatedAt.Add(maxAge), stored.ExpiresAt, "the session never outlives its maximum age")
}

func TestAuthService_Refresh_Rejections(t *testing.T) {
	t.Parallel()
	boom := errors.New("backend down")
	tests := []struct {
		name    string
		empty   bool
		maxAge  time.Duration
		setup   func(f *authFixture, user *domain.User, hash string, session *domain.Session)
		code    string
		message string
	}{
		{
			name:    "empty token",
			empty:   true,
			code:    apperror.CodeUnauthorized,
			message: msgRefreshRejected,
		},
		{
			name: "unknown token",
			setup: func(f *authFixture, _ *domain.User, hash string, _ *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(nil, apperror.NotFound("session", hash))
				f.sessions.EXPECT().ConsumedBy(gomock.Any(), hash).Return(int64(0), nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgRefreshRejected,
		},
		{
			name: "session store failure",
			setup: func(f *authFixture, _ *domain.User, hash string, _ *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(nil, boom)
			},
			code:    apperror.CodeInternal,
			message: msgLoadSessionFailed,
		},
		{
			name: "consumption lookup failure",
			setup: func(f *authFixture, _ *domain.User, hash string, _ *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(nil, apperror.NotFound("session", hash))
				f.sessions.EXPECT().ConsumedBy(gomock.Any(), hash).Return(int64(0), boom)
			},
			code:    apperror.CodeInternal,
			message: msgLoadSessionFailed,
		},
		{
			name: "user no longer exists",
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, apperror.NotFound("user", user.ID))
			},
			code:    apperror.CodeUnauthorized,
			message: msgRefreshRejected,
		},
		{
			name: "user lookup failure",
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, boom)
			},
			code:    apperror.CodeInternal,
			message: msgLoadUserFailed,
		},
		{
			name: "blocked user loses the session",
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				user.IsBlocked = true
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgAccountBlocked,
		},
		{
			name: "temporary password must be changed first",
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				user.PasswordTemporary = true
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgPasswordChangeRequired,
		},
		{
			name: "session started before the password was changed",
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				session.CreatedAt = user.PasswordChangedAt.Add(-time.Second)
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgRefreshRejected,
		},
		{
			name:   "session reached its maximum age",
			maxAge: 30 * time.Minute,
			setup: func(f *authFixture, user *domain.User, hash string, session *domain.Session) {
				f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(session, nil)
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgRefreshRejected,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t, func(c *AuthConfig) { c.SessionMaxAge = tc.maxAge })
			user := f.user()
			token, hash, session := refreshFixture(user, f.now, 'b')
			if tc.empty {
				token = ""
			}
			if tc.setup != nil {
				tc.setup(f, user, hash, session)
			}

			pair, err := f.svc.Refresh(t.Context(), token, f.meta)

			assert.Nil(t, pair)
			appErr := requireAppError(t, err, tc.code)
			assert.Equal(t, tc.message, appErr.Message)
		})
	}
}

func TestAuthService_Refresh_SessionStartedWithinThePasswordChangeSecondIsKept(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	user.PasswordChangedAt = f.now.Add(-time.Hour).Add(700 * time.Millisecond)
	oldToken, oldHash, current := refreshFixture(user, f.now, 'k')
	current.CreatedAt = f.now.Add(-time.Hour)
	f.sessions.EXPECT().Take(gomock.Any(), oldHash, testRefreshTTL).Return(current, nil)
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.revocations.EXPECT().RevokeToken(gomock.Any(), current.AccessJTI, gomock.Any()).Return(nil)
	f.expectIssue(user, nil)
	expectAudit(f.audit, domain.AuditActionTokenRefresh)

	_, err := f.svc.Refresh(t.Context(), oldToken, f.meta)

	require.NoError(t, err, "stored session times have second resolution")
}

func TestAuthService_Refresh_ReplayRevokesEverySession(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	token, hash, _ := refreshFixture(user, f.now, 'r')
	gomock.InOrder(
		f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(nil, apperror.NotFound("session", hash)),
		f.sessions.EXPECT().ConsumedBy(gomock.Any(), hash).Return(user.ID, nil),
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(2, nil),
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), user.ID, f.now, testAccessTTL+revocationGrace).Return(nil),
	)
	event := expectAudit(f.audit, domain.AuditActionTokenReuse)

	pair, err := f.svc.Refresh(t.Context(), token, f.meta)

	assert.Nil(t, pair)
	appErr := requireAppError(t, err, apperror.CodeUnauthorized)
	assert.Equal(t, msgRefreshRejected, appErr.Message)
	assert.Equal(t, user.ID, event.ActorID)
	assert.Equal(t, f.meta, event.ClientMeta)
	assert.Equal(t, map[string]any{"sid": sessionID(hash), "sessions_revoked": 2}, event.Details)
}

func TestAuthService_Refresh_ReplayRevocationFailureIsInternal(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	token, hash, _ := refreshFixture(user, f.now, 's')
	f.sessions.EXPECT().Take(gomock.Any(), hash, testRefreshTTL).Return(nil, apperror.NotFound("session", hash))
	f.sessions.EXPECT().ConsumedBy(gomock.Any(), hash).Return(user.ID, nil)
	f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(0, errors.New("redis down"))

	_, err := f.svc.Refresh(t.Context(), token, f.meta)

	requireAppError(t, err, apperror.CodeInternal)
}

var _ port.AuthService = (*AuthService)(nil)
