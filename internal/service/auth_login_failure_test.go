package service

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/metrics"
)

func TestAuthService_Login_UnknownUserIsRejectedAndCounted(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
	f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(nil, apperror.NotFound("user", testEmail))
	f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(1), nil)
	event := expectAudit(f.audit, domain.AuditActionLoginFailed)

	res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

	assert.Nil(t, res)
	appErr := requireAppError(t, err, apperror.CodeUnauthorized)
	assert.Equal(t, msgLoginRejected, appErr.Message)
	assert.Equal(t, http.StatusUnauthorized, appErr.HTTPStatus)
	assert.Zero(t, event.ActorID)
	assert.Equal(t, testEmail, event.ResourceID)
	assert.Equal(t, map[string]any{"reason": "user_not_found", "attempts": int64(1), "locked": false}, event.Details)
}

func TestAuthService_Login_BoundsTheAuditResourceID(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	email := strings.Repeat("a", maxResourceIDBytes) + "@example.com"
	f.attempts.EXPECT().IsLocked(gomock.Any(), email).Return(false, nil)
	f.users.EXPECT().FindByEmail(gomock.Any(), email).Return(nil, apperror.NotFound("user", email))
	f.attempts.EXPECT().RecordFailure(gomock.Any(), email, testLockout).Return(int64(1), nil)
	event := expectAudit(f.audit, domain.AuditActionLoginFailed)

	_, err := f.svc.Login(t.Context(), email, testPassword, f.meta)

	requireAppError(t, err, apperror.CodeUnauthorized)
	assert.Equal(t, strings.Repeat("a", maxResourceIDBytes), event.ResourceID, "the address is cut to what the audit store accepts")
}

func TestAuthService_Login_WrongPasswordCountsFailuresAndLocks(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		failures int64
		locked   bool
	}{
		{"below the limit", testMaxAttempts - 1, false},
		{"at the limit", testMaxAttempts, true},
		{"beyond the limit", testMaxAttempts + 2, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			user := f.user()
			f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
			f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
			f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(tc.failures, nil)
			if tc.locked {
				f.attempts.EXPECT().Lock(gomock.Any(), testEmail, testLockout).Return(nil)
			}
			event := expectAudit(f.audit, domain.AuditActionLoginFailed)

			res, err := f.svc.Login(t.Context(), testEmail, "not-the-password", f.meta)

			assert.Nil(t, res)
			appErr := requireAppError(t, err, apperror.CodeUnauthorized)
			assert.Equal(t, msgLoginRejected, appErr.Message)
			assert.Equal(t, user.ID, event.ActorID)
			assert.Equal(t, "42", event.ResourceID)
			assert.Equal(t, map[string]any{"reason": "invalid_password", "attempts": tc.failures, "locked": tc.locked}, event.Details)
		})
	}
}

func TestAuthService_Login_LockedAccountIsRejectedBeforeLookup(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(true, nil)
	event := expectAudit(f.audit, domain.AuditActionLoginLocked)

	res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

	assert.Nil(t, res)
	appErr := requireAppError(t, err, apperror.CodeUnauthorized)
	assert.Equal(t, msgAccountLocked, appErr.Message)
	assert.Zero(t, event.ActorID)
	assert.Equal(t, testEmail, event.ResourceID)
	assert.Equal(t, map[string]any{"reason": "too_many_failed_attempts"}, event.Details)
}

func TestAuthService_Login_BlockedUser(t *testing.T) {
	t.Parallel()
	t.Run("gets the wrong-password answer after the password check", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		user.IsBlocked = true
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
		f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
		event := expectAudit(f.audit, domain.AuditActionLoginFailed)

		res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

		assert.Nil(t, res)
		appErr := requireAppError(t, err, apperror.CodeUnauthorized)
		assert.Equal(t, msgLoginRejected, appErr.Message, "the block is not disclosed to the caller")
		assert.Equal(t, user.ID, event.ActorID)
		assert.Equal(t, map[string]any{"reason": "user_blocked"}, event.Details, "the audit entry keeps the real reason")
	})
	t.Run("with a wrong password is not told about the block", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		user := f.user()
		user.IsBlocked = true
		f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
		f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
		f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(1), nil)
		expectAudit(f.audit, domain.AuditActionLoginFailed)

		_, err := f.svc.Login(t.Context(), testEmail, "not-the-password", f.meta)

		appErr := requireAppError(t, err, apperror.CodeUnauthorized)
		assert.Equal(t, msgLoginRejected, appErr.Message)
	})
}

func TestAuthService_Login_InfrastructureFailuresAreInternal(t *testing.T) {
	t.Parallel()
	boom := errors.New("backend down")
	tests := []struct {
		name  string
		setup func(f *authFixture, user *domain.User)
	}{
		{
			name: "user lookup",
			setup: func(f *authFixture, _ *domain.User) {
				f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
				f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(nil, boom)
			},
		},
		{
			name: "role lookup",
			setup: func(f *authFixture, user *domain.User) {
				f.expectCredentialsOK(user)
				f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return(nil, boom)
			},
		},
		{
			name: "session creation",
			setup: func(f *authFixture, user *domain.User) {
				f.expectCredentialsOK(user)
				f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return(nil, nil)
				f.sessions.EXPECT().Create(gomock.Any(), gomock.Any(), testRefreshTTL).Return(boom)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			tc.setup(f, f.user())

			res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

			assert.Nil(t, res)
			requireAppError(t, err, apperror.CodeInternal)
			require.ErrorIs(t, err, boom)
		})
	}
}

// TestAuthService_Login_FailsClosedWhenTheAttemptStoreIsDown pins that the lockout is never
// bypassed: when the store cannot answer, no credential is checked and nothing is disclosed.
func TestAuthService_Login_FailsClosedWhenTheAttemptStoreIsDown(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	tests := []struct {
		name     string
		password string
		setup    func(f *authFixture, user *domain.User) *domain.AuditEvent
		details  map[string]any
	}{
		{
			name:     "lock probe failure refuses the login before the lookup",
			password: testPassword,
			setup: func(f *authFixture, _ *domain.User) *domain.AuditEvent {
				f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, boom)
				return nil
			},
		},
		{
			name:     "failure counter outage refuses a bad password",
			password: "not-the-password",
			setup: func(f *authFixture, user *domain.User) *domain.AuditEvent {
				f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
				f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
				f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(0), boom)
				return expectAudit(f.audit, domain.AuditActionLoginFailed)
			},
			details: map[string]any{"reason": "invalid_password"},
		},
		{
			name:     "lock failure refuses a bad password at the limit",
			password: "not-the-password",
			setup: func(f *authFixture, user *domain.User) *domain.AuditEvent {
				f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
				f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
				f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(testMaxAttempts), nil)
				f.attempts.EXPECT().Lock(gomock.Any(), testEmail, testLockout).Return(boom)
				return expectAudit(f.audit, domain.AuditActionLoginFailed)
			},
			details: map[string]any{"reason": "invalid_password", "attempts": int64(testMaxAttempts)},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			event := tc.setup(f, f.user())

			res, err := f.svc.Login(t.Context(), testEmail, tc.password, f.meta)

			assert.Nil(t, res)
			appErr := requireAppError(t, err, apperror.CodeServiceUnavailable)
			assert.Equal(t, msgLoginUnavailable, appErr.Message)
			assert.Equal(t, http.StatusServiceUnavailable, appErr.HTTPStatus)
			if event != nil {
				assert.Equal(t, tc.details, event.Details)
			}
		})
	}
}

func TestAuthService_Login_ToleratesBestEffortFailures(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	f := newAuthFixture(t)
	user := f.user()
	f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
	f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
	f.attempts.EXPECT().Reset(gomock.Any(), testEmail).Return(boom)
	f.expectIssue(user, nil)
	f.audit.EXPECT().Record(gomock.Any(), auditAction(domain.AuditActionLoginSuccess)).Return(boom)

	res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

	require.NoError(t, err, "a counter that cannot be reset and an audit store that is down do not block a valid login")
	assert.NotNil(t, res.Tokens)
}

// TestAuthService_Login_RecordsAttemptMetrics runs sequentially on purpose: the counters are
// process-wide and parallel tests would move them while it reads.
func TestAuthService_Login_RecordsAttemptMetrics(t *testing.T) {
	read := func(result string) float64 {
		return testutil.ToFloat64(metrics.AuthAttempts.WithLabelValues(result))
	}
	success, failure, locked := read(metrics.ResultSuccess), read(metrics.ResultFailure), read(metrics.ResultLocked)
	f := newAuthFixture(t)
	user := f.user()
	f.expectCredentialsOK(user)
	f.expectIssue(user, nil)
	expectAudit(f.audit, domain.AuditActionLoginSuccess)
	f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(false, nil)
	f.users.EXPECT().FindByEmail(gomock.Any(), testEmail).Return(user, nil)
	f.attempts.EXPECT().RecordFailure(gomock.Any(), testEmail, testLockout).Return(int64(1), nil)
	expectAudit(f.audit, domain.AuditActionLoginFailed)
	f.attempts.EXPECT().IsLocked(gomock.Any(), testEmail).Return(true, nil)
	expectAudit(f.audit, domain.AuditActionLoginLocked)

	_, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)
	require.NoError(t, err)
	_, err = f.svc.Login(t.Context(), testEmail, "not-the-password", f.meta)
	requireAppError(t, err, apperror.CodeUnauthorized)
	_, err = f.svc.Login(t.Context(), testEmail, testPassword, f.meta)
	requireAppError(t, err, apperror.CodeUnauthorized)

	assert.InDelta(t, success+1, read(metrics.ResultSuccess), 0)
	assert.InDelta(t, failure+1, read(metrics.ResultFailure), 0)
	assert.InDelta(t, locked+1, read(metrics.ResultLocked), 0)
}
