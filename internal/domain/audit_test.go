package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAuditLog_TableName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "audit_logs", AuditLog{}.TableName())
}

func TestAuditActions(t *testing.T) {
	t.Parallel()
	actions := map[string]string{
		"login success":   AuditActionLoginSuccess,
		"login failed":    AuditActionLoginFailed,
		"login locked":    AuditActionLoginLocked,
		"logout":          AuditActionLogout,
		"logout all":      AuditActionLogoutAll,
		"token refresh":   AuditActionTokenRefresh,
		"token reuse":     AuditActionTokenReuse,
		"password change": AuditActionPasswordChange,
		"session revoke":  AuditActionSessionRevoke,
		"user create":     AuditActionUserCreate,
		"user block":      AuditActionUserBlock,
		"user unblock":    AuditActionUserUnblock,
	}
	want := map[string]string{
		"login success":   "auth.login.success",
		"login failed":    "auth.login.failed",
		"login locked":    "auth.login.locked",
		"logout":          "auth.logout",
		"logout all":      "auth.logout_all",
		"token refresh":   "auth.token.refresh",
		"token reuse":     "auth.token.reuse",
		"password change": "auth.password.change",
		"session revoke":  "auth.session.revoke",
		"user create":     "user.create",
		"user block":      "user.block",
		"user unblock":    "user.unblock",
	}

	assert.Equal(t, want, actions, "audit action names are an external contract")

	seen := make(map[string]string, len(actions))
	for name, action := range actions {
		other, dup := seen[action]
		assert.False(t, dup, "%s and %s share the action %q", name, other, action)
		seen[action] = name
	}
}
