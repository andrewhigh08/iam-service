package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

// auditCtxKey tags the context of an audit test so the test can tell it was passed through.
type auditCtxKey struct{}

func newAuditService(t *testing.T) (*AuditService, *mocks.MockAuditLogRepository, time.Time) {
	t.Helper()
	repo := mocks.NewMockAuditLogRepository(gomock.NewController(t))
	svc, err := NewAuditService(repo, nil)
	require.NoError(t, err)
	now := time.Now().Truncate(time.Second)
	svc.now = func() time.Time { return now }
	return svc, repo, now
}

func TestNewAuditService_RequiresRepository(t *testing.T) {
	t.Parallel()

	svc, err := NewAuditService(nil, nil)

	require.ErrorContains(t, err, "repository is required")
	assert.Nil(t, svc)
}

func TestAuditService_Record_PersistsEntryInCallerContext(t *testing.T) {
	t.Parallel()
	svc, repo, now := newAuditService(t)
	ctx := context.WithValue(t.Context(), auditCtxKey{}, "tx")
	var stored domain.AuditLog
	repo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(got context.Context, entry *domain.AuditLog) error {
		assert.Equal(t, "tx", got.Value(auditCtxKey{}), "the caller's context, and so its transaction, is passed through")
		stored = *entry
		return nil
	})

	err := svc.Record(ctx, domain.AuditEvent{
		ActorID:      1,
		Action:       domain.AuditActionUserCreate,
		ResourceType: domain.AuditResourceTypeUser,
		ResourceID:   "7",
		Details:      map[string]any{"email": "bob@example.com", "temporary": true},
		ClientMeta:   domain.ClientMeta{IP: "203.0.113.9", UserAgent: "admin-ui/2.0"},
	})

	require.NoError(t, err)
	assert.Zero(t, stored.ID)
	assert.Equal(t, int64(1), stored.ActorID)
	assert.Equal(t, domain.AuditActionUserCreate, stored.Action)
	assert.Equal(t, domain.AuditResourceTypeUser, stored.ResourceType)
	assert.Equal(t, "7", stored.ResourceID)
	assert.Equal(t, now, stored.CreatedAt)
	assert.JSONEq(t, `{"email":"bob@example.com","temporary":true}`, string(stored.Details))
	require.NotNil(t, stored.IPAddress)
	assert.Equal(t, "203.0.113.9", *stored.IPAddress)
	require.NotNil(t, stored.UserAgent)
	assert.Equal(t, "admin-ui/2.0", *stored.UserAgent)
}

func TestAuditService_Record_StoresEmptyMetadataAsNull(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		details map[string]any
	}{
		{"nil details", nil},
		{"empty details", map[string]any{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc, repo, _ := newAuditService(t)
			var stored domain.AuditLog
			repo.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, entry *domain.AuditLog) error {
				stored = *entry
				return nil
			})

			err := svc.Record(t.Context(), domain.AuditEvent{Action: domain.AuditActionLogout, Details: tc.details})

			require.NoError(t, err)
			assert.Nil(t, stored.Details)
			assert.Nil(t, stored.IPAddress)
			assert.Nil(t, stored.UserAgent)
		})
	}
}

func TestAuditService_Record_Rejections(t *testing.T) {
	t.Parallel()
	t.Run("event without an action", func(t *testing.T) {
		t.Parallel()
		svc, _, _ := newAuditService(t)

		err := svc.Record(t.Context(), domain.AuditEvent{ActorID: 1})

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "audit event has no action", appErr.Message)
	})
	t.Run("details that cannot be encoded", func(t *testing.T) {
		t.Parallel()
		svc, _, _ := newAuditService(t)

		err := svc.Record(t.Context(), domain.AuditEvent{Action: domain.AuditActionLogout, Details: map[string]any{"ch": make(chan int)}})

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to encode audit details", appErr.Message)
	})
	t.Run("repository failure", func(t *testing.T) {
		t.Parallel()
		svc, repo, _ := newAuditService(t)
		boom := errors.New("db down")
		repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(boom)

		err := svc.Record(t.Context(), domain.AuditEvent{Action: domain.AuditActionLogout})

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to store audit entry", appErr.Message)
		require.ErrorIs(t, err, boom)
	})
	t.Run("repository application error keeps its code", func(t *testing.T) {
		t.Parallel()
		svc, repo, _ := newAuditService(t)
		repo.EXPECT().Create(gomock.Any(), gomock.Any()).Return(apperror.ServiceUnavailable("database is read-only"))

		err := svc.Record(t.Context(), domain.AuditEvent{Action: domain.AuditActionLogout})

		appErr := requireAppError(t, err, apperror.CodeServiceUnavailable)
		assert.Equal(t, "database is read-only", appErr.Message)
	})
}

func TestAuditService_ListByActor(t *testing.T) {
	t.Parallel()
	t.Run("returns the repository entries", func(t *testing.T) {
		t.Parallel()
		svc, repo, now := newAuditService(t)
		entries := []domain.AuditLog{{ID: 2, ActorID: 7, Action: domain.AuditActionLogout, CreatedAt: now}}
		repo.EXPECT().ListByUser(gomock.Any(), int64(7), 25).Return(entries, nil)

		got, err := svc.ListByActor(t.Context(), 7, 25)

		require.NoError(t, err)
		assert.Equal(t, entries, got)
	})
	t.Run("wraps repository failures", func(t *testing.T) {
		t.Parallel()
		svc, repo, _ := newAuditService(t)
		boom := errors.New("db down")
		repo.EXPECT().ListByUser(gomock.Any(), int64(7), 0).Return(nil, boom)

		got, err := svc.ListByActor(t.Context(), 7, 0)

		assert.Nil(t, got)
		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to list audit entries", appErr.Message)
		require.ErrorIs(t, err, boom)
	})
}
