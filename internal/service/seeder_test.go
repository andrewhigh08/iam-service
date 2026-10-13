package service

import (
	"context"
	"errors"
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

// Administrator credentials used by the seeder tests.
const (
	adminEmail    = "admin@example.com"
	adminPassword = "Admin-Secret-9!"
)

// seederFixture is a Seeder on a mock user repository and a real, in-memory authorization
// service, so that the seeded policies and roles can be checked through the enforcer.
type seederFixture struct {
	seeder   *Seeder
	users    *mocks.MockUserRepository
	authz    *AuthorizationService
	enforcer casbin.IEnforcer
}

func newSeederFixture(t *testing.T) *seederFixture {
	t.Helper()
	authz, enforcer := newAuthz(t)
	users := mocks.NewMockUserRepository(gomock.NewController(t))
	seeder, err := NewSeeder(users, authz, nil)
	require.NoError(t, err)
	return &seederFixture{
		seeder:   seeder,
		users:    users,
		authz:    authz,
		enforcer: enforcer,
	}
}

func TestNewSeeder_RejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	f := newSeederFixture(t)
	tests := []struct {
		name  string
		users port.UserRepository
		authz PolicyAuthorizer
	}{
		{"nothing", nil, nil},
		{"users only", f.users, nil},
		{"authz only", nil, f.authz},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			seeder, err := NewSeeder(tc.users, tc.authz, nil)
			require.ErrorContains(t, err, "are required")
			assert.Nil(t, seeder)
		})
	}
}

func (f *seederFixture) expectAdminInsert() *domain.User {
	inserted := &domain.User{}
	f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(nil, apperror.NotFound("user", adminEmail))
	f.users.EXPECT().Create(gomock.Any(), gomock.Any()).DoAndReturn(func(_ context.Context, u *domain.User) error {
		u.ID = createdID
		*inserted = *u
		return nil
	})
	return inserted
}

func existingAdmin() *domain.User {
	return &domain.User{ID: createdID, Email: adminEmail, FullName: adminFullName}
}

// TestSeeder_Seed_RequiresDependencies covers a Seeder built as a literal, which Seed checks itself.
func TestSeeder_Seed_RequiresDependencies(t *testing.T) {
	t.Parallel()
	f := newSeederFixture(t)
	tests := []struct {
		name   string
		seeder *Seeder
	}{
		{"nothing", &Seeder{}},
		{"users only", &Seeder{Users: f.users}},
		{"authz only", &Seeder{Authz: f.authz}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.ErrorContains(t, tc.seeder.Seed(t.Context(), adminEmail, adminPassword), "are required")
		})
	}
}

func TestSeeder_Seed_InstallsPoliciesAndAdmin(t *testing.T) {
	t.Parallel()
	f := newSeederFixture(t)
	ctx := t.Context()
	inserted := f.expectAdminInsert()

	require.NoError(t, f.seeder.Seed(ctx, " Admin@Example.com ", adminPassword))

	assert.Equal(t, adminEmail, inserted.Email)
	assert.Equal(t, adminFullName, inserted.FullName)
	assert.False(t, inserted.PasswordTemporary)
	assert.False(t, inserted.IsBlocked)
	assert.False(t, inserted.PasswordChangedAt.IsZero(), "a fresh admin password is not expired")
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(inserted.PasswordHash), []byte(adminPassword)))
	roles, err := f.authz.RolesOf(ctx, createdID)
	require.NoError(t, err)
	assert.Equal(t, []string{domain.RoleAdmin}, roles)
	allowed, err := f.authz.CheckAccess(ctx, createdID, domain.ResourceUsers, domain.ActionWrite)
	require.NoError(t, err)
	assert.True(t, allowed)
	assert.Equal(t, len(domain.DefaultPolicies()), policyCount(t, f.enforcer))
}

func TestSeeder_Seed_IsIdempotent(t *testing.T) {
	t.Parallel()
	t.Run("an existing admin with the role is left alone", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		ctx := t.Context()
		require.NoError(t, f.authz.AssignRole(ctx, createdID, domain.RoleAdmin))
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(existingAdmin(), nil).Times(2)

		require.NoError(t, f.seeder.Seed(ctx, adminEmail, adminPassword))
		require.NoError(t, f.seeder.Seed(ctx, adminEmail, adminPassword))

		roles, err := f.authz.RolesOf(ctx, createdID)
		require.NoError(t, err)
		assert.Equal(t, []string{domain.RoleAdmin}, roles)
		assert.Equal(t, len(domain.DefaultPolicies()), policyCount(t, f.enforcer))
	})
	t.Run("an existing account without the role is granted it", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		ctx := t.Context()
		require.NoError(t, f.authz.AssignRole(ctx, createdID, domain.RoleViewer))
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(existingAdmin(), nil)

		require.NoError(t, f.seeder.Seed(ctx, adminEmail, adminPassword))

		roles, err := f.authz.RolesOf(ctx, createdID)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{domain.RoleViewer, domain.RoleAdmin}, roles)
	})
}

func TestSeeder_Seed_SkipsAdminWithoutEmail(t *testing.T) {
	t.Parallel()
	f := newSeederFixture(t)

	require.NoError(t, f.seeder.Seed(t.Context(), "   ", ""))

	assert.Equal(t, len(domain.DefaultPolicies()), policyCount(t, f.enforcer), "policies are installed anyway")
}

func TestSeeder_Seed_RequiresAdminPassword(t *testing.T) {
	t.Parallel()
	f := newSeederFixture(t)

	err := f.seeder.Seed(t.Context(), adminEmail, "")

	appErr := requireAppError(t, err, apperror.CodeInternal)
	assert.Equal(t, "admin password is required to seed the administrator", appErr.Message)
	assert.Equal(t, len(domain.DefaultPolicies()), policyCount(t, f.enforcer), "policies are installed anyway")
}

func TestSeeder_Seed_Failures(t *testing.T) {
	t.Parallel()
	boom := errors.New("db down")
	t.Run("lookup failure", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(nil, boom)

		err := f.seeder.Seed(t.Context(), adminEmail, adminPassword)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to check admin account", appErr.Message)
		require.ErrorIs(t, err, boom)
	})
	t.Run("insert failure", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(nil, apperror.NotFound("user", adminEmail))
		f.users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(boom)

		err := f.seeder.Seed(t.Context(), adminEmail, adminPassword)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to create admin account", appErr.Message)
	})
	t.Run("insert conflict is an error, the advisory lock rules out a race", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(nil, apperror.NotFound("user", adminEmail))
		f.users.EXPECT().Create(gomock.Any(), gomock.Any()).Return(apperror.Conflict("user", "email", adminEmail))

		err := f.seeder.Seed(t.Context(), adminEmail, adminPassword)

		requireAppError(t, err, apperror.CodeConflict)
		roles, rolesErr := f.authz.RolesOf(t.Context(), createdID)
		require.NoError(t, rolesErr)
		assert.Empty(t, roles)
	})
	t.Run("role assignment failure is reported for the transaction to roll back", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		f.seeder.Authz = newBrokenAuthz(t)
		f.expectAdminInsert()

		err := f.seeder.Seed(t.Context(), adminEmail, adminPassword)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to assign role", appErr.Message)
	})
	t.Run("role lookup failure for an existing admin", func(t *testing.T) {
		t.Parallel()
		f := newSeederFixture(t)
		f.seeder.Authz = newBrokenAuthz(t)
		f.users.EXPECT().FindByEmail(gomock.Any(), adminEmail).Return(existingAdmin(), nil)

		err := f.seeder.Seed(t.Context(), adminEmail, adminPassword)

		appErr := requireAppError(t, err, apperror.CodeInternal)
		assert.Equal(t, "failed to load roles", appErr.Message)
	})
}
