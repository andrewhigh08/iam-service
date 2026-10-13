package service

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

func TestUserService_Block_DisablesAccountAndRevokesAccess(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	user := newTestUser(t, f.now)
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.expectTx()
	f.expectTxSetBlocked(user.ID, true)
	event := f.expectTxAudit(domain.AuditActionUserBlock)
	gomock.InOrder(
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(3, nil),
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), user.ID, f.now, testAccessTTL+revocationGrace).Return(nil),
	)

	require.NoError(t, f.svc.Block(t.Context(), user.ID, f.actor))

	assert.True(t, user.IsBlocked)
	assert.Equal(t, f.actor.UserID, event.ActorID)
	assert.Equal(t, "42", event.ResourceID)
	assert.Equal(t, f.actor.ClientMeta, event.ClientMeta)
	assert.Equal(t, map[string]any{"email": user.Email}, event.Details)
}

func TestUserService_Block_RepeatsRevocationForABlockedUser(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	user := newTestUser(t, f.now)
	user.IsBlocked = true
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	gomock.InOrder(
		f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(1, nil),
		f.revocations.EXPECT().RevokeUserTokensBefore(gomock.Any(), user.ID, f.now, testAccessTTL+revocationGrace).Return(nil),
	)

	require.NoError(t, f.svc.Block(t.Context(), user.ID, f.actor), "a block whose revocation failed can be retried")
}

func TestUserService_Block_Rejections(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	tests := []struct {
		name    string
		setup   func(f *userFixture, user *domain.User)
		code    string
		message string
	}{
		{
			name: "unknown user",
			setup: func(f *userFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, apperror.NotFound("user", user.ID))
			},
			code:    apperror.CodeNotFound,
			message: "user not found",
		},
		{
			name: "lookup failure",
			setup: func(f *userFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(nil, boom)
			},
			code:    apperror.CodeInternal,
			message: msgLoadUserFailed,
		},
		{
			name: "update failure rolls back before the audit entry",
			setup: func(f *userFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectTx()
				f.users.EXPECT().SetBlocked(gomock.Any(), user.ID, true).Return(boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to update user",
		},
		{
			name: "audit failure rolls back the block",
			setup: func(f *userFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectTx()
				f.users.EXPECT().SetBlocked(gomock.Any(), user.ID, true).Return(nil)
				f.audit.EXPECT().Record(gomock.Any(), auditAction(domain.AuditActionUserBlock)).Return(boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to update user",
		},
		{
			name: "revocation failure after the block was stored",
			setup: func(f *userFixture, user *domain.User) {
				f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
				f.expectTx()
				f.users.EXPECT().SetBlocked(gomock.Any(), user.ID, true).Return(nil)
				f.audit.EXPECT().Record(gomock.Any(), auditAction(domain.AuditActionUserBlock)).Return(nil)
				f.sessions.EXPECT().DeleteAllForUser(gomock.Any(), user.ID).Return(0, boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to delete sessions",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newUserFixture(t)
			user := newTestUser(t, f.now)
			tc.setup(f, user)

			err := f.svc.Block(t.Context(), user.ID, f.actor)

			appErr := requireAppError(t, err, tc.code)
			assert.Equal(t, tc.message, appErr.Message)
		})
	}
}

func TestUserService_Unblock_ReenablesAccount(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	user := newTestUser(t, f.now)
	user.IsBlocked = true
	f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)
	f.expectTx()
	f.expectTxSetBlocked(user.ID, false)
	event := f.expectTxAudit(domain.AuditActionUserUnblock)

	require.NoError(t, f.svc.Unblock(t.Context(), user.ID, f.actor))

	assert.False(t, user.IsBlocked)
	assert.Equal(t, f.actor.UserID, event.ActorID)
	assert.Equal(t, map[string]any{"email": user.Email}, event.Details)
}

func TestUserService_Unblock_Rejections(t *testing.T) {
	t.Parallel()
	t.Run("active user", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		user := newTestUser(t, f.now)
		f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)

		err := f.svc.Unblock(t.Context(), user.ID, f.actor)

		appErr := requireAppError(t, err, apperror.CodeBadRequest)
		assert.Equal(t, "user is not blocked", appErr.Message)
	})
	t.Run("unknown user", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().FindByID(gomock.Any(), testUserID).Return(nil, apperror.NotFound("user", testUserID))

		requireAppError(t, f.svc.Unblock(t.Context(), testUserID, f.actor), apperror.CodeNotFound)
	})
}

func TestUserService_GetByID(t *testing.T) {
	t.Parallel()
	t.Run("returns the user", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		user := newTestUser(t, f.now)
		f.users.EXPECT().FindByID(gomock.Any(), user.ID).Return(user, nil)

		got, err := f.svc.GetByID(t.Context(), user.ID)

		require.NoError(t, err)
		assert.Same(t, user, got)
	})
	t.Run("keeps not found", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().FindByID(gomock.Any(), testUserID).Return(nil, apperror.NotFound("user", testUserID))

		got, err := f.svc.GetByID(t.Context(), testUserID)

		assert.Nil(t, got)
		requireAppError(t, err, apperror.CodeNotFound)
	})
	t.Run("wraps repository failures", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		boom := errors.New("db down")
		f.users.EXPECT().FindByID(gomock.Any(), testUserID).Return(nil, boom)

		_, err := f.svc.GetByID(t.Context(), testUserID)

		requireAppError(t, err, apperror.CodeInternal)
		require.ErrorIs(t, err, boom)
	})
}

func TestUserService_List(t *testing.T) {
	t.Parallel()
	filter := port.UserFilter{Status: "blocked", Search: "ali", Page: 2, PageSize: 10}
	t.Run("passes the filter through", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		users := []domain.User{*newTestUser(t, f.now)}
		f.users.EXPECT().List(gomock.Any(), filter).Return(users, int64(11), nil)

		got, total, err := f.svc.List(t.Context(), filter)

		require.NoError(t, err)
		assert.Equal(t, users, got)
		assert.Equal(t, int64(11), total)
	})
	t.Run("wraps repository failures", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		f.users.EXPECT().List(gomock.Any(), filter).Return(nil, int64(0), errors.New("db down"))

		got, total, err := f.svc.List(t.Context(), filter)

		assert.Nil(t, got)
		assert.Zero(t, total)
		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to list users", appErr.Message)
	})
}
