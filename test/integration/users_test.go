package integration

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleBasedAccessControl(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)

	// Viewers and analysts may read users but never write them.
	for _, role := range []string{roleViewer, roleAnalyst} {
		t.Run(role, func(t *testing.T) {
			t.Parallel()
			acc := c.mustCreateUser(t, admin, role, false)
			token := c.mustLogin(t, acc.Email, acc.Password).AccessToken

			list := c.do(t, http.MethodGet, "/api/v1/users", nil, token)
			requireStatus(t, list, http.StatusOK)
			var users usersData
			list.decode(t, &users)
			assert.NotEmpty(t, users.Users)
			require.NotNil(t, list.Meta)
			assert.Equal(t, 1, list.Meta.Page)
			assert.Equal(t, 10, list.Meta.PageSize)
			assert.Positive(t, list.Meta.Total)
			assert.Equal(t, acc.Email, c.getUser(t, token, acc.ID).Email)

			req := createUserRequest{Email: uniqueEmail(t), Password: initialPassword, FullName: "Nobody", Role: roleViewer}
			denied := requireError(t, c.createUser(t, token, req), http.StatusForbidden, "FORBIDDEN")
			assert.Equal(t, "insufficient permissions", denied.Message)
			requireError(t, c.do(t, http.MethodPost, userPath(acc.ID, "/block"), nil, token), http.StatusForbidden, "FORBIDDEN")
			requireError(t, c.do(t, http.MethodPost, userPath(acc.ID, "/unblock"), nil, token), http.StatusForbidden, "FORBIDDEN")
		})
	}
}

func TestBlockRevokesAccessAndUnblockRestoresIt(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)
	acc := c.mustCreateUser(t, admin, roleViewer, false)
	pair := c.mustLogin(t, acc.Email, acc.Password)
	requireStatus(t, c.sessions(t, pair.AccessToken), http.StatusOK)

	blocked := c.do(t, http.MethodPost, userPath(acc.ID, "/block"), nil, admin)
	requireStatus(t, blocked, http.StatusOK)
	var msg messageData
	blocked.decode(t, &msg)
	assert.Equal(t, "user blocked", msg.Message)

	// The token issued moments ago, most likely within the same second, is dead at once.
	denied := requireError(t, c.sessions(t, pair.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid or expired token", denied.Message)
	requireError(t, c.refresh(t, pair.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	rejected := requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid credentials", rejected.Message, "a blocked account answers like a wrong password")
	assert.True(t, c.getUser(t, admin, acc.ID).IsBlocked)

	// Blocking again repeats the revocation instead of failing, so a block can be retried.
	again := c.do(t, http.MethodPost, userPath(acc.ID, "/block"), nil, admin)
	requireStatus(t, again, http.StatusOK)
	again.decode(t, &msg)
	assert.Equal(t, "user blocked", msg.Message)

	unblocked := c.do(t, http.MethodPost, userPath(acc.ID, "/unblock"), nil, admin)
	requireStatus(t, unblocked, http.StatusOK)
	unblocked.decode(t, &msg)
	assert.Equal(t, "user unblocked", msg.Message)
	assert.False(t, c.getUser(t, admin, acc.ID).IsBlocked)
	restored := c.mustLogin(t, acc.Email, acc.Password)
	requireStatus(t, c.sessions(t, restored.AccessToken), http.StatusOK)

	notBlocked := requireError(t, c.do(t, http.MethodPost, userPath(acc.ID, "/unblock"), nil, admin), http.StatusBadRequest, "BAD_REQUEST")
	assert.Equal(t, "user is not blocked", notBlocked.Message)
}

func TestUserEndpointsValidateTheID(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)

	tests := []struct {
		name    string
		method  string
		path    string
		status  int
		code    string
		message string
	}{
		{name: "get non-numeric", method: http.MethodGet, path: "/api/v1/users/abc", status: http.StatusBadRequest, code: "BAD_REQUEST", message: "invalid user id"},
		{name: "get zero", method: http.MethodGet, path: "/api/v1/users/0", status: http.StatusBadRequest, code: "BAD_REQUEST", message: "invalid user id"},
		{name: "unblock negative", method: http.MethodPost, path: "/api/v1/users/-1/unblock", status: http.StatusBadRequest, code: "BAD_REQUEST", message: "invalid user id"},
		{name: "get unknown", method: http.MethodGet, path: "/api/v1/users/987654321", status: http.StatusNotFound, code: "NOT_FOUND", message: "user not found"},
		{name: "block unknown", method: http.MethodPost, path: "/api/v1/users/987654321/block", status: http.StatusNotFound, code: "NOT_FOUND", message: "user not found"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			errBody := requireError(t, c.do(t, tc.method, tc.path, nil, admin), tc.status, tc.code)
			assert.Equal(t, tc.message, errBody.Message)
		})
	}
}

func TestWrongOldPasswordCountsTowardsLockout(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)
	token := c.mustLogin(t, acc.Email, acc.Password).AccessToken

	for range lockoutMaxAttempts {
		body := map[string]string{"old_password": wrongPassword, "new_password": "An0ther!Secret"}
		denied := requireError(t, c.do(t, http.MethodPost, "/api/v1/change-password", body, token), http.StatusUnauthorized, "UNAUTHORIZED")
		assert.Equal(t, "invalid old password", denied.Message)
	}

	// The account is locked for the password change as well as for logins.
	body := map[string]string{"old_password": acc.Password, "new_password": "An0ther!Secret"}
	locked := requireError(t, c.do(t, http.MethodPost, "/api/v1/change-password", body, token), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "account temporarily locked", locked.Message)
	assert.Equal(t, "account temporarily locked", requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED").Message)
}

func TestLockoutAfterRepeatedFailures(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)

	for attempt := range lockoutMaxAttempts {
		denied := requireError(t, c.login(t, acc.Email, wrongPassword), http.StatusUnauthorized, "UNAUTHORIZED")
		assert.Equalf(t, "invalid credentials", denied.Message, "attempt %d", attempt+1)
	}
	locked := requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "account temporarily locked", locked.Message)

	// The forced password change shares the lock, and the lock is per account.
	forced := c.do(t, http.MethodPost, "/auth/change-password", map[string]string{
		"email": acc.Email, "old_password": acc.Password, "new_password": "An0ther!Secret",
	}, "")
	assert.Equal(t, "account temporarily locked", requireError(t, forced, http.StatusUnauthorized, "UNAUTHORIZED").Message)
	c.adminToken(t)
}
