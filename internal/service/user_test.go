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
	"github.com/andrewhigh08/iam-service/test/mocks"
)

const createdID int64 = 7

// txMarker is the context key under which the fake transaction manager tags the context it
// hands to the transactional function.
type txMarker struct{}

func inTx(ctx context.Context) bool {
	tagged, _ := ctx.Value(txMarker{}).(bool)
	return tagged
}

// userFixture is a UserService wired to gomock collaborators with a frozen clock.
type userFixture struct {
	t           *testing.T
	svc         *UserService
	users       *mocks.MockUserRepository
	tx          *mocks.MockTxManager
	authz       *mocks.MockAuthorizationService
	audit       *mocks.MockAuditService
	sessions    *mocks.MockSessionStore
	revocations *mocks.MockRevocationStore
	now         time.Time
	actor       domain.Actor
}

func newUserFixture(t *testing.T) *userFixture {
	t.Helper()
	ctrl := gomock.NewController(t)
	f := &userFixture{
		t:           t,
		users:       mocks.NewMockUserRepository(ctrl),
		tx:          mocks.NewMockTxManager(ctrl),
		authz:       mocks.NewMockAuthorizationService(ctrl),
		audit:       mocks.NewMockAuditService(ctrl),
		sessions:    mocks.NewMockSessionStore(ctrl),
		revocations: mocks.NewMockRevocationStore(ctrl),
		now:         time.Now().Truncate(time.Second),
		actor:       domain.Actor{UserID: 1, ClientMeta: domain.ClientMeta{IP: "203.0.113.9", UserAgent: "admin-ui/2.0"}},
	}
	svc, err := NewUserService(f.deps())
	require.NoError(t, err)
	svc.now = func() time.Time { return f.now }
	f.svc = svc
	return f
}

func (f *userFixture) deps() UserDeps {
	return UserDeps{
		Users:       f.users,
		Tx:          f.tx,
		Authz:       f.authz,
		Audit:       f.audit,
		Sessions:    f.sessions,
		Revocations: f.revocations,
		AccessTTL:   testAccessTTL,
	}
}

func (f *userFixture) expectTx() {
	f.tx.EXPECT().WithinTx(gomock.Any(), gomock.Any()).DoAndReturn(
		func(ctx context.Context, fn func(context.Context) error) error {
			return fn(context.WithValue(ctx, txMarker{}, true))
		})
}

func (f *userFixture) expectTxSetBlocked(userID int64, blocked bool) {
	f.users.EXPECT().SetBlocked(gomock.Any(), userID, blocked).DoAndReturn(func(ctx context.Context, _ int64, _ bool) error {
		assert.True(f.t, inTx(ctx), "the update must run inside the transaction")
		return nil
	})
}

func (f *userFixture) expectTxAudit(action string) *domain.AuditEvent {
	recorded := &domain.AuditEvent{}
	f.audit.EXPECT().Record(gomock.Any(), auditAction(action)).DoAndReturn(func(ctx context.Context, e domain.AuditEvent) error {
		assert.True(f.t, inTx(ctx), "the audit entry must share the transaction")
		*recorded = e
		return nil
	})
	return recorded
}

func TestNewUserService_RejectsInvalidDeps(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*UserDeps)
		want   string
	}{
		{"user repository", func(d *UserDeps) { d.Users = nil }, "user repository is required"},
		{"transaction manager", func(d *UserDeps) { d.Tx = nil }, "transaction manager is required"},
		{"authorization service", func(d *UserDeps) { d.Authz = nil }, "authorization service is required"},
		{"audit service", func(d *UserDeps) { d.Audit = nil }, "audit service is required"},
		{"session store", func(d *UserDeps) { d.Sessions = nil }, "session store is required"},
		{"revocation store", func(d *UserDeps) { d.Revocations = nil }, "revocation store is required"},
		{"access TTL", func(d *UserDeps) { d.AccessTTL = 0 }, "access TTL must be positive"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := newUserFixture(t).deps()
			tc.mutate(&deps)
			svc, err := NewUserService(deps)
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, svc)
		})
	}
}

func TestUserService_Create_RegistersUserWithRole(t *testing.T) {
	t.Parallel()
	f := newUserFixture(t)
	in := port.CreateUserInput{
		Email:     " Bob@Example.com ",
		Password:  testNewPassword,
		FullName:  "  Bob Builder ",
		Role:      domain.RoleAnalyst,
		Temporary: true,
	}
	f.users.EXPECT().ExistsByEmail(gomock.Any(), "bob@example.com").Return(false, nil)
	f.users.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		u.ID = createdID
		return nil
	})
	f.authz.EXPECT().AssignRole(gomock.Any(), createdID, domain.RoleAnalyst).Return(nil)
	event := expectAudit(f.audit, domain.AuditActionUserCreate)

	user, err := f.svc.Create(t.Context(), in, f.actor)

	require.NoError(t, err)
	assert.Equal(t, createdID, user.ID)
	assert.Equal(t, "bob@example.com", user.Email)
	assert.Equal(t, "Bob Builder", user.FullName)
	assert.True(t, user.PasswordTemporary)
	assert.False(t, user.IsBlocked)
	assert.Equal(t, f.now, user.PasswordChangedAt)
	assert.Equal(t, f.now, user.CreatedAt)
	assert.Equal(t, f.now, user.UpdatedAt)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(testNewPassword)))
	assert.Equal(t, f.actor.UserID, event.ActorID)
	assert.Equal(t, domain.AuditResourceTypeUser, event.ResourceType)
	assert.Equal(t, "7", event.ResourceID)
	assert.Equal(t, f.actor.ClientMeta, event.ClientMeta)
	assert.Equal(t, map[string]any{"email": "bob@example.com", "full_name": "Bob Builder", "role": domain.RoleAnalyst, "temporary": true}, event.Details)
}

func TestUserService_Create_Rejections(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	tests := []struct {
		name    string
		mutate  func(*port.CreateUserInput)
		setup   func(f *userFixture)
		code    string
		message string
	}{
		{
			name:    "unknown role",
			mutate:  func(in *port.CreateUserInput) { in.Role = "superuser" },
			code:    apperror.CodeValidation,
			message: "invalid role",
		},
		{
			name:    "blank email",
			mutate:  func(in *port.CreateUserInput) { in.Email = "   " },
			code:    apperror.CodeValidation,
			message: "invalid email",
		},
		{
			name:    "weak password",
			mutate:  func(in *port.CreateUserInput) { in.Password = "password" },
			code:    apperror.CodeValidation,
			message: msgPolicyFailed,
		},
		{
			name: "duplicate email",
			setup: func(f *userFixture) {
				f.users.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(true, nil)
			},
			code:    apperror.CodeConflict,
			message: "user with this email already exists",
		},
		{
			name: "email check failure",
			setup: func(f *userFixture) {
				f.users.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to check email",
		},
		{
			name: "insert conflict keeps its code",
			setup: func(f *userFixture) {
				f.users.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
				f.users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(apperror.Conflict("user", "email", testEmail))
			},
			code:    apperror.CodeConflict,
			message: "user with this email already exists",
		},
		{
			name: "insert failure",
			setup: func(f *userFixture) {
				f.users.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
				f.users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(boom)
			},
			code:    apperror.CodeInternal,
			message: "failed to create user",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newUserFixture(t)
			in := port.CreateUserInput{Email: testEmail, Password: testPassword, FullName: "Alice", Role: domain.RoleViewer}
			if tc.mutate != nil {
				tc.mutate(&in)
			}
			if tc.setup != nil {
				tc.setup(f)
			}

			user, err := f.svc.Create(t.Context(), in, f.actor)

			assert.Nil(t, user)
			appErr := requireAppError(t, err, tc.code)
			assert.Equal(t, tc.message, appErr.Message)
		})
	}
}

func TestUserService_Create_RemovesUserWhenRoleAssignmentFails(t *testing.T) {
	t.Parallel()
	assignErr := errors.New("enforcer down")
	deleteErr := errors.New("delete failed")
	setup := func(f *userFixture) {
		f.users.EXPECT().ExistsByEmail(gomock.Any(), testEmail).Return(false, nil)
		f.users.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
			u.ID = createdID
			return nil
		})
		f.authz.EXPECT().AssignRole(gomock.Any(), createdID, domain.RoleViewer).Return(assignErr)
	}
	in := port.CreateUserInput{Email: testEmail, Password: testPassword, Role: domain.RoleViewer}
	t.Run("compensation succeeds", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		setup(f)
		f.users.EXPECT().HardDelete(gomock.Any(), createdID).Return(nil)

		user, err := f.svc.Create(t.Context(), in, f.actor)

		assert.Nil(t, user)
		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to assign role", appErr.Message)
		require.ErrorIs(t, err, assignErr)
	})
	t.Run("compensation fails", func(t *testing.T) {
		t.Parallel()
		f := newUserFixture(t)
		setup(f)
		f.users.EXPECT().HardDelete(gomock.Any(), createdID).Return(deleteErr)

		user, err := f.svc.Create(t.Context(), in, f.actor)

		assert.Nil(t, user)
		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to assign role and to remove the user", appErr.Message)
		require.ErrorIs(t, err, assignErr)
		require.ErrorIs(t, err, deleteErr)
	})
}
