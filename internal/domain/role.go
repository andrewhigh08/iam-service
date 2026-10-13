package domain

// Roles that can be assigned to a user.
const (
	RoleAdmin   = "admin"
	RoleAnalyst = "analyst"
	RoleViewer  = "viewer"
)

// Resources and actions referenced by access policies.
const (
	ResourceUsers = "users"
	ResourceAudit = "audit"

	ActionRead  = "read"
	ActionWrite = "write"
)

// ValidRoles returns every assignable role.
func ValidRoles() []string {
	return []string{RoleAdmin, RoleAnalyst, RoleViewer}
}

// IsValidRole reports whether role is one of ValidRoles.
func IsValidRole(role string) bool {
	switch role {
	case RoleAdmin, RoleAnalyst, RoleViewer:
		return true
	default:
		return false
	}
}

// Policy grants a role the permission to perform Action on Resource.
type Policy struct {
	Role     string
	Resource string
	Action   string
}

// DefaultPolicies returns the role permissions seeded at startup.
func DefaultPolicies() []Policy {
	return []Policy{
		{Role: RoleAdmin, Resource: ResourceUsers, Action: ActionRead},
		{Role: RoleAdmin, Resource: ResourceUsers, Action: ActionWrite},
		{Role: RoleAdmin, Resource: ResourceAudit, Action: ActionRead},
		{Role: RoleAnalyst, Resource: ResourceUsers, Action: ActionRead},
		{Role: RoleAnalyst, Resource: ResourceAudit, Action: ActionRead},
		{Role: RoleViewer, Resource: ResourceUsers, Action: ActionRead},
	}
}
