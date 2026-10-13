package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// expectUnlocked expects the lock probe and the counter reset of an authenticated password
// change whose old password is right.
func (f *authFixture) expectUnlocked(user *domain.User) {
	f.attempts.EXPECT().IsLocked(gomock.Any(), user.Email).Return(false, nil)
	f.attempts.EXPECT().Reset(gomock.Any(), user.Email).Return(nil)
}

// expectPasswordReplacement expects what follows a verified password change: the password
// update, the user-wide revocation and the re-issue, in that order. It returns the hash that
// was written and the new session as it was stored.
func (f *authFixture) expectPasswordReplacement(user *domain.User, removed int) (*string, *domain.Session) {
	written := new(string)
	stored, create := f.expectSessionCreate()
	f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return([]string{domain.RoleViewer}, nil)
	gomock.InOrder(
		f.users.EXPECT().UpdatePassword(gomock.Any(), user.ID, gomock.Any(), false, f.now).
			DoAndReturn(func(_ context.Context, _ int64, hash string, _ bool, _ time.Time) error {
				*written = hash
				return nil
			}),
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(removed, nil),
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), user.ID, f.now, testAccessTTL+revocationGrace).Return(nil),
		create,
	)
	return written, stored
}

// assertPasswordReplaced checks that the written hash carries newPassword, that the user in
// memory follows the stored state, and that pair belongs to the stored session.
func assertPasswordReplaced(t *testing.T, f *authFixture, user *domain.User, written string, stored *domain.Session, pair *port.TokenPair, newPassword string) {
	t.Helper()
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(written), []byte(newPassword)))
	assert.Equal(t, written, user.PasswordHash)
	assert.False(t, user.PasswordTemporary)
	assert.Equal(t, f.now, user.PasswordChangedAt)
	require.NotNil(t, pair)
	assert.Equal(t, hashToken(pair.RefreshToken), stored.TokenHash)
	assert.Equal(t, stored.ID, f.parseClaims(pair.AccessToken).SessionID)
}

func TestAuthService_ChangePassword_ReplacesPasswordAndReissues(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	user.PasswordTemporary = true
	oldHash := user.PasswordHash
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.expectUnlocked(user)
	written, stored := f.expectPasswordReplacement(user, 1)
	event := expectAudit(f.audit, domain.AuditActionPasswordChange)

	pair, err := f.svc.ChangePassword(t.Context(), user.ID, testPassword, testNewPassword, f.meta)

	require.NoError(t, err)
	assertPasswordReplaced(t, f, user, *written, stored, pair, testNewPassword)
	assert.NotEqual(t, oldHash, *written)
	assert.Equal(t, user.ID, event.ActorID)
	assert.Equal(t, f.meta, event.ClientMeta)
	assert.Equal(t, map[string]any{"forced": false, "sessions_revoked": 1, "sid": stored.ID}, event.Details)
}

func TestAuthService_ChangePassword_WrongOldPasswordCountsTowardsLockout(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		failures int64
		locked   bool
	}{
		{"below the limit", testMaxAttempts - 1, false},
		{"at the limit", testMaxAttempts, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			user := f.user()
			f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			f.attempts.EXPECT().IsLocked(gomock.Any(), user.Email).Return(false, nil)
			f.attempts.EXPECT().RecordFailure(gomock.Any(), user.Email, testLockout).Return(tc.failures, nil)
			if tc.locked {
				f.attempts.EXPECT().Lock(gomock.Any(), user.Email, testLockout).Return(nil)
			}
			event := expectAudit(f.audit, domain.AuditActionLoginFailed)

			pair, err := f.svc.ChangePassword(t.Context(), user.ID, "not-the-password", testNewPassword, f.meta)

			assert.Nil(t, pair)
			appErr := requireAppError(t, err, apperror.CodeUnauthorized)
			assert.Equal(t, "invalid old password", appErr.Message)
			assert.Equal(t, user.ID, event.ActorID)
			assert.Equal(t, "42", event.ResourceID)
			assert.Equal(t, map[string]any{"reason": "invalid_old_password", "attempts": tc.failures, "locked": tc.locked}, event.Details)
		})
	}
}

func TestAuthService_ChangePassword_Rejections(t *testing.T) {
	t.Parallel()
	boom := errors.New("backend down")
	tests := []struct {
		name        string
		oldPassword string
		newPassword string
		setup       func(f *authFixture, user *domain.User)
		code        string
		message     string
	}{
		{
			name:        "blocked user",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				user.IsBlocked = true
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
			},
			code:    apperror.CodeUnauthorized,
			message: msgAccountBlocked,
		},
		{
			name:        "locked account",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.attempts.EXPECT().IsLocked(gomock.Any(), user.Email).Return(true, nil)
				event := expectAudit(f.audit, domain.AuditActionLoginLocked)
				_ = event
			},
			code:    apperror.CodeUnauthorized,
			message: msgAccountLocked,
		},
		{
			name:        "lock probe failure fails closed",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.attempts.EXPECT().IsLocked(gomock.Any(), user.Email).Return(false, boom)
			},
			code:    apperror.CodeServiceUnavailable,
			message: msgLoginUnavailable,
		},
		{
			name:        "new password violates the policy",
			oldPassword: testPassword,
			newPassword: "weak",
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectUnlocked(user)
			},
			code:    apperror.CodeValidation,
			message: msgPolicyFailed,
		},
		{
			name:        "new password equals the current one",
			oldPassword: testPassword,
			newPassword: testPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectUnlocked(user)
			},
			code:    apperror.CodeValidation,
			message: msgPolicyFailed,
		},
		{
			name:        "unknown user",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, apperror.NotFound("user", user.ID))
			},
			code:    apperror.CodeNotFound,
			message: "user not found",
		},
		{
			name:        "user lookup failure",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, boom)
			},
			code:    apperror.CodeInternal,
			message: msgLoadUserFailed,
		},
		{
			name:        "update failure",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectUnlocked(user)
				f.users.EXPECT().UpdatePassword(gomock.Any(), user.ID, gomock.Any(), false, f.now).Return(boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to update password",
		},
		{
			name:        "revocation failure after the update",
			oldPassword: testPassword,
			newPassword: testNewPassword,
			setup: func(f *authFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectUnlocked(user)
				f.users.EXPECT().UpdatePassword(gomock.Any(), user.ID, gomock.Any(), false, f.now).Return(nil)
				f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(0, boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to delete sessions",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			user := f.user()
			tc.setup(f, user)

			pair, err := f.svc.ChangePassword(t.Context(), user.ID, tc.oldPassword, tc.newPassword, f.meta)

			assert.Nil(t, pair)
			appErr := requireAppError(t, err, tc.code)
			assert.Equal(t, tc.message, appErr.Message)
		})
	}
}

func TestAuthService_ChangePassword_ReportsPolicyViolations(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.expectUnlocked(user)

	_, err := f.svc.ChangePassword(t.Context(), user.ID, testPassword, "short", f.meta)

	appErr := requireAppError(t, err, apperror.CodeValidation)
	violations, ok := appErr.Details["errors"].([]string)
	require.True(t, ok)
	assert.NotEmpty(t, violations)
}

func TestAuthService_ChangeRequiredPassword_ReplacesForcedPasswords(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		maxAge  time.Duration
		prepare func(u *domain.User, now time.Time)
		reason  string
	}{
		{
			name:    "temporary password",
			prepare: func(u *domain.User, _ time.Time) { u.PasswordTemporary = true },
			reason:  port.ReasonTemporaryPassword,
		},
		{
			name:    "expired password",
			maxAge:  24 * time.Hour,
			prepare: func(u *domain.User, now time.Time) { u.PasswordChangedAt = now.Add(-48 * time.Hour) },
			reason:  port.ReasonPasswordExpired,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t, func(c *AuthConfig) { c.PasswordMaxAge = tc.maxAge })
			user := f.user()
			tc.prepare(user, f.now)
			f.expectCredentialsOK(user)
			written, stored := f.expectPasswordReplacement(user, 0)
			event := expectAudit(f.audit, domain.AuditActionPasswordChange)

			pair, err := f.svc.ChangeRequiredPassword(t.Context(), "  "+testEmail+" ", testPassword, testNewPassword, f.meta)

			require.NoError(t, err)
			assertPasswordReplaced(t, f, user, *written, stored, pair, testNewPassword)
			assert.Equal(t, map[string]any{"forced": true, "reason": tc.reason, "sessions_revoked": 0, "sid": stored.ID}, event.Details)
		})
	}
}

func TestAuthService_ChangeRequiredPassword_Rejections(t *testing.T) {
	t.Parallel()
	t.Run("current password that needs no change", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		f.expectCredentialsOK(user)

		pair, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, testPassword, testNewPassword, f.meta)

		assert.Nil(t, pair)
		appErr := requireAppError(t, err, apperror.CodeBadRequest)
		assert.Equal(t, "password change not required", appErr.Message)
	})
	t.Run("wrong old password counts towards the lockout", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		user.PasswordTemporary = true
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
		f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
		f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(testMaxAttempts), nil)
		f.attempts.EXPECT().Lock(gomock.Any(), testEmail, testLockout).Return(nil)
		expectAudit(f.audit, domain.AuditActionLoginFailed)

		_, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, "not-the-password", testNewPassword, f.meta)

		appErr := requireAppError(t, err, apperror.CodeUnauthorized)
		assert.Equal(t, msgLoginRejected, appErr.Message)
	})
	t.Run("locked account", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(true, nil)
		expectAudit(f.audit, domain.AuditActionLoginLocked)

		_, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, testPassword, testNewPassword, f.meta)

		appErr := requireAppError(t, err, apperror.CodeUnauthorized)
		assert.Equal(t, msgAccountLocked, appErr.Message)
	})
	t.Run("attempt store outage fails closed", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, errors.New("redis down"))

		_, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, testPassword, testNewPassword, f.meta)

		requireAppError(t, err, apperror.CodeServiceUnavailable)
	})
	t.Run("unknown account", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
		f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(nil, apperror.NotFound("user", testEmail))
		f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(1), nil)
		expectAudit(f.audit, domain.AuditActionLoginFailed)

		_, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, testPassword, testNewPassword, f.meta)

		appErr := requireAppError(t, err, apperror.CodeUnauthorized)
		assert.Equal(t, msgLoginRejected, appErr.Message)
	})
	t.Run("weak new password is rejected before anything is written", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		user.PasswordTemporary = true
		f.expectCredentialsOK(user)

		_, err := f.svc.ChangeRequiredPassword(t.Context(), testEmail, testPassword, "weak", f.meta)

		requireAppError(t, err, apperror.CodeValidation)
	})
}
