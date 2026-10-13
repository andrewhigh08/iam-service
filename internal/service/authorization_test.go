package service

import (
	"testing"

	"github.com/casbin/casbin/v3"
	"github.com/casbin/casbin/v3/model"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/metrics"
)

// casbinModelPath is the production model, relative to this package.
const casbinModelPath = "../../configs/casbin_model.conf"

// modelWithoutRoles is the production model minus its role definition: policies can still be
// stored, but every RBAC operation of the enforcer fails.
const modelWithoutRoles = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// newEnforcer returns an in-memory enforcer for m: no adapter, so policies live only in memory.
func newEnforcer(t *testing.T, m model.Model) casbin.IEnforcer {
	t.Helper()
	enforcer, err := casbin.NewEnforcer(m)
	require.NoError(t, err)
	return enforcer
}

// newAuthz returns an AuthorizationService on the production model with in-memory policies,
// together with its enforcer for direct inspection.
func newAuthz(t *testing.T) (*AuthorizationService, casbin.IEnforcer) {
	t.Helper()
	m, err := model.NewModelFromFile(casbinModelPath)
	require.NoError(t, err)
	enforcer := newEnforcer(t, m)
	svc, err := NewAuthorizationService(enforcer, nil)
	require.NoError(t, err)
	return svc, enforcer
}

// newBrokenAuthz returns an AuthorizationService whose enforcer rejects every RBAC operation.
func newBrokenAuthz(t *testing.T) *AuthorizationService {
	t.Helper()
	m, err := model.NewModelFromString(modelWithoutRoles)
	require.NoError(t, err)
	svc, err := NewAuthorizationService(newEnforcer(t, m), nil)
	require.NoError(t, err)
	return svc
}

func policyCount(t *testing.T, enforcer casbin.IEnforcer) int {
	t.Helper()
	policies, err := enforcer.GetPolicy()
	require.NoError(t, err)
	return len(policies)
}

func TestNewAuthorizationService_RequiresEnforcer(t *testing.T) {
	t.Parallel()

	svc, err := NewAuthorizationService(nil, nil)

	require.ErrorContains(t, err, "enforcer is required")
	assert.Nil(t, svc)
}

func TestAuthorizationService_CheckAccess_FollowsRoleInheritance(t *testing.T) {
	t.Parallel()
	svc, _ := newAuthz(t)
	ctx := t.Context()
	require.NoError(t, svc.EnsurePolicies(ctx, domain.DefaultPolicies()))
	require.NoError(t, svc.AssignRole(ctx, 1, domain.RoleAdmin))
	require.NoError(t, svc.AssignRole(ctx, 2, domain.RoleAnalyst))
	require.NoError(t, svc.AssignRole(ctx, 3, domain.RoleViewer))

	tests := []struct {
		name     string
		userID   int64
		resource string
		action   string
		allowed  bool
	}{
		{"admin reads users", 1, domain.ResourceUsers, domain.ActionRead, true},
		{"admin writes users", 1, domain.ResourceUsers, domain.ActionWrite, true},
		{"admin reads audit", 1, domain.ResourceAudit, domain.ActionRead, true},
		{"analyst reads users", 2, domain.ResourceUsers, domain.ActionRead, true},
		{"analyst cannot write users", 2, domain.ResourceUsers, domain.ActionWrite, false},
		{"analyst reads audit", 2, domain.ResourceAudit, domain.ActionRead, true},
		{"viewer reads users", 3, domain.ResourceUsers, domain.ActionRead, true},
		{"viewer cannot write users", 3, domain.ResourceUsers, domain.ActionWrite, false},
		{"viewer cannot read audit", 3, domain.ResourceAudit, domain.ActionRead, false},
		{"user without a role", 4, domain.ResourceUsers, domain.ActionRead, false},
		{"unknown resource", 1, "secrets", domain.ActionRead, false},
		{"unknown action", 1, domain.ResourceUsers, "delete", false},
	}
	// The subtests share one plain (unsynchronized) enforcer, so they run sequentially.
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, err := svc.CheckAccess(ctx, tc.userID, tc.resource, tc.action)

			require.NoError(t, err)
			assert.Equal(t, tc.allowed, allowed)
		})
	}
}

func TestAuthorizationService_EnsurePolicies_IsIdempotent(t *testing.T) {
	t.Parallel()
	svc, enforcer := newAuthz(t)
	ctx := t.Context()
	defaults := domain.DefaultPolicies()
	_, err := enforcer.AddPolicy(roleName(domain.RoleViewer), domain.ResourceUsers, domain.ActionRead)
	require.NoError(t, err, "one rule is pre-installed")

	require.NoError(t, svc.EnsurePolicies(ctx, defaults))
	require.NoError(t, svc.EnsurePolicies(ctx, defaults))

	assert.Equal(t, len(defaults), policyCount(t, enforcer))
	for _, p := range defaults {
		has, hasErr := enforcer.HasPolicy(roleName(p.Role), p.Resource, p.Action)
		require.NoError(t, hasErr)
		assert.Truef(t, has, "policy %s %s %s is installed", p.Role, p.Resource, p.Action)
	}
}

func TestAuthorizationService_AssignRole(t *testing.T) {
	t.Parallel()
	t.Run("grants a role once", func(t *testing.T) {
		t.Parallel()
		svc, _ := newAuthz(t)
		ctx := t.Context()

		require.NoError(t, svc.AssignRole(ctx, 1, domain.RoleViewer))
		require.NoError(t, svc.AssignRole(ctx, 1, domain.RoleViewer))

		roles, err := svc.RolesOf(ctx, 1)
		require.NoError(t, err)
		assert.Equal(t, []string{domain.RoleViewer}, roles)
	})
	t.Run("accumulates roles", func(t *testing.T) {
		t.Parallel()
		svc, _ := newAuthz(t)
		ctx := t.Context()

		require.NoError(t, svc.AssignRole(ctx, 2, domain.RoleViewer))
		require.NoError(t, svc.AssignRole(ctx, 2, domain.RoleAnalyst))

		roles, err := svc.RolesOf(ctx, 2)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{domain.RoleViewer, domain.RoleAnalyst}, roles)
	})
	t.Run("rejects an unknown role", func(t *testing.T) {
		t.Parallel()
		svc, _ := newAuthz(t)
		ctx := t.Context()

		err := svc.AssignRole(ctx, 3, "root")

		appErr := requireAppError(t, err, apperror.CodeValidation)
		assert.Equal(t, "invalid role", appErr.Message)
		roles, err := svc.RolesOf(ctx, 3)
		require.NoError(t, err)
		assert.Empty(t, roles)
	})
}

func TestAuthorizationService_RolesOf_StripsRolePrefix(t *testing.T) {
	t.Parallel()
	svc, enforcer := newAuthz(t)
	ctx := t.Context()
	_, err := enforcer.AddGroupingPolicy(subject(9), roleName(domain.RoleAdmin))
	require.NoError(t, err)
	_, err = enforcer.AddGroupingPolicy(subject(9), "group:ops")
	require.NoError(t, err, "a grouping that is not a role")

	roles, err := svc.RolesOf(ctx, 9)
	require.NoError(t, err)
	assert.Equal(t, []string{domain.RoleAdmin}, roles)

	none, err := svc.RolesOf(ctx, 10)
	require.NoError(t, err)
	assert.NotNil(t, none, "a user without roles gets an empty list, not nil")
	assert.Empty(t, none)
}

func TestAuthorizationService_EnforcerFailuresAreInternal(t *testing.T) {
	t.Parallel()
	svc := newBrokenAuthz(t)
	ctx := t.Context()

	allowed, err := svc.CheckAccess(ctx, 1, domain.ResourceUsers, domain.ActionRead)
	assert.False(t, allowed)
	appErr := requireAppError(t, err, apperror.CodeInternal)
	assert.Equal(t, "authorization check failed", appErr.Message)

	appErr = requireAppError(t, svc.AssignRole(ctx, 1, domain.RoleAdmin), apperror.CodeInternal)
	assert.Equal(t, "failed to assign role", appErr.Message)

	roles, err := svc.RolesOf(ctx, 1)
	assert.Nil(t, roles)
	appErr = requireAppError(t, err, apperror.CodeInternal)
	assert.Equal(t, "failed to load roles", appErr.Message)

	require.NoError(t, svc.EnsurePolicies(ctx, domain.DefaultPolicies()), "policies do not need the role section")
}

// TestAuthorizationService_CheckAccess_RecordsDecisions runs sequentially on purpose: the
// counters are process-wide and parallel tests would move them while it reads.
func TestAuthorizationService_CheckAccess_RecordsDecisions(t *testing.T) {
	const resource, action = "reports", "export"
	read := func(result string) float64 {
		return testutil.ToFloat64(metrics.AuthzDecisions.WithLabelValues(result, resource, action))
	}
	svc, enforcer := newAuthz(t)
	ctx := t.Context()
	_, err := enforcer.AddPolicy(roleName(domain.RoleAnalyst), resource, action)
	require.NoError(t, err)
	require.NoError(t, svc.AssignRole(ctx, 1, domain.RoleAnalyst))
	allowed, denied := read(metrics.ResultAllowed), read(metrics.ResultDenied)

	ok, err := svc.CheckAccess(ctx, 1, resource, action)
	require.NoError(t, err)
	assert.True(t, ok)
	ok, err = svc.CheckAccess(ctx, 2, resource, action)
	require.NoError(t, err)
	assert.False(t, ok)

	assert.InDelta(t, allowed+1, read(metrics.ResultAllowed), 0)
	assert.InDelta(t, denied+1, read(metrics.ResultDenied), 0)
}
