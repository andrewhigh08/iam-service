package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValidRole(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		role string
		want bool
	}{
		{name: "admin", role: RoleAdmin, want: true},
		{name: "analyst", role: RoleAnalyst, want: true},
		{name: "viewer", role: RoleViewer, want: true},
		{name: "empty", role: ""},
		{name: "different case", role: "Admin"},
		{name: "surrounding whitespace", role: "admin "},
		{name: "casbin subject format", role: "role:admin"},
		{name: "unknown", role: "root"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, IsValidRole(tt.role))
		})
	}
}

func TestValidRoles(t *testing.T) {
	t.Parallel()
	roles := ValidRoles()

	assert.Equal(t, []string{RoleAdmin, RoleAnalyst, RoleViewer}, roles)
	for _, role := range roles {
		assert.True(t, IsValidRole(role), "role %q", role)
	}
}

func TestValidRoles_ReturnsAFreshSlice(t *testing.T) {
	t.Parallel()
	roles := ValidRoles()
	roles[0] = "tampered"

	assert.Equal(t, RoleAdmin, ValidRoles()[0])
}

func TestDefaultPolicies(t *testing.T) {
	t.Parallel()
	want := []Policy{
		{Role: RoleAdmin, Resource: ResourceUsers, Action: ActionRead},
		{Role: RoleAdmin, Resource: ResourceUsers, Action: ActionWrite},
		{Role: RoleAdmin, Resource: ResourceAudit, Action: ActionRead},
		{Role: RoleAnalyst, Resource: ResourceUsers, Action: ActionRead},
		{Role: RoleAnalyst, Resource: ResourceAudit, Action: ActionRead},
		{Role: RoleViewer, Resource: ResourceUsers, Action: ActionRead},
	}

	policies := DefaultPolicies()

	assert.ElementsMatch(t, want, policies)
	granted := make(map[string]bool, len(policies))
	for _, p := range policies {
		granted[p.Role] = true
	}
	for _, role := range ValidRoles() {
		assert.True(t, granted[role], "role %q has no policy", role)
	}
}

func TestDefaultPolicies_OnlyAdminWrites(t *testing.T) {
	t.Parallel()
	for _, p := range DefaultPolicies() {
		if p.Action == ActionWrite {
			assert.Equal(t, RoleAdmin, p.Role, "policy %+v grants write to a non-admin role", p)
		}
	}
}
