package integration

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestListUsersFiltersAndPaginates(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)
	// Both addresses share a prefix of their own, which narrows every listing to these two users.
	prefix := uniquePrefix(t)
	active := c.mustCreateUserWithEmail(t, admin, prefix+"-active@example.com", roleViewer, false)
	blocked := c.mustCreateUserWithEmail(t, admin, prefix+"-blocked@example.com", roleAnalyst, false)
	requireStatus(t, c.do(t, http.MethodPost, userPath(blocked.ID, "/block"), nil, admin), http.StatusOK)
	search := "search=" + url.QueryEscape(prefix)
	list := func(query string) (usersData, metaBody) {
		resp := c.do(t, http.MethodGet, "/api/v1/users?"+query, nil, admin)
		requireStatus(t, resp, http.StatusOK)
		var data usersData
		resp.decode(t, &data)
		require.NotNil(t, resp.Meta)
		return data, *resp.Meta
	}
	emails := func(data usersData) []string {
		out := make([]string, 0, len(data.Users))
		for _, u := range data.Users {
			out = append(out, u.Email)
		}
		return out
	}

	all, meta := list(search)
	assert.ElementsMatch(t, []string{active.Email, blocked.Email}, emails(all))
	assert.Equal(t, metaBody{Page: 1, PageSize: 10, Total: 2, TotalPages: 1}, meta)

	onlyActive, _ := list("status=active&" + search)
	assert.Equal(t, []string{active.Email}, emails(onlyActive))
	assert.False(t, onlyActive.Users[0].IsBlocked)
	onlyBlocked, _ := list("status=blocked&" + search)
	assert.Equal(t, []string{blocked.Email}, emails(onlyBlocked))
	assert.True(t, onlyBlocked.Users[0].IsBlocked)
	everyone, _ := list("status=all&" + search)
	assert.Len(t, everyone.Users, 2)

	// Pages of one are served newest first; the page size is capped at 100.
	first, meta := list("page_size=1&" + search)
	assert.Equal(t, []string{blocked.Email}, emails(first))
	assert.Equal(t, metaBody{Page: 1, PageSize: 1, Total: 2, TotalPages: 2}, meta)
	second, meta := list("page=2&page_size=1&" + search)
	assert.Equal(t, []string{active.Email}, emails(second))
	assert.Equal(t, 2, meta.Page)
	_, meta = list("page_size=1000&" + search)
	assert.Equal(t, 100, meta.PageSize)

	invalid := requireError(t, c.do(t, http.MethodGet, "/api/v1/users?status=unknown", nil, admin), http.StatusBadRequest, "BAD_REQUEST")
	assert.Equal(t, "status must be one of: all, active, blocked", invalid.Message)
}

func TestCreateUserValidatesInputAndRejectsDuplicates(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)
	valid := createUserRequest{Email: uniqueEmail(t), Password: initialPassword, FullName: "  Valid User  ", Role: roleViewer}

	created := c.createUser(t, admin, valid)
	requireStatus(t, created, http.StatusCreated)
	assert.True(t, created.Success)
	var user userData
	created.decode(t, &user)
	assert.Positive(t, user.ID)
	assert.Equal(t, valid.Email, user.Email)
	assert.Equal(t, "Valid User", user.FullName)
	assert.WithinDuration(t, time.Now(), user.CreatedAt, time.Minute)
	assert.Equal(t, time.UTC, user.CreatedAt.Location())

	modified := func(change func(r *createUserRequest)) createUserRequest {
		r := valid
		change(&r)
		return r
	}
	tests := []struct {
		name   string
		body   any
		status int
		code   string
		check  func(t *testing.T, e errorBody)
	}{
		{
			name:   "weak password",
			body:   modified(func(r *createUserRequest) { r.Password = "weak" }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check: func(t *testing.T, e errorBody) {
				assert.Equal(t, "password does not meet the policy", e.Message)
				assert.Contains(t, e.Details["errors"], "password must be at least 8 characters long")
			},
		},
		{
			name:   "common password",
			body:   modified(func(r *createUserRequest) { r.Password = "Password1!" }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check: func(t *testing.T, e errorBody) {
				assert.Equal(t, []any{"password is too common"}, e.Details["errors"])
			},
		},
		{
			name:   "password longer than bcrypt can hash",
			body:   modified(func(r *createUserRequest) { r.Password = "Aa1!" + strings.Repeat("ж", 40) }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check: func(t *testing.T, e errorBody) {
				assert.Contains(t, e.Details["errors"], "password must not exceed 72 bytes in UTF-8; non-ASCII characters take several bytes each")
			},
		},
		{
			name:   "unknown role",
			body:   modified(func(r *createUserRequest) { r.Role = "root" }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check:  func(t *testing.T, e errorBody) { assert.Equal(t, "oneof=admin analyst viewer", fieldRule(e, "role")) },
		},
		{
			name:   "malformed email",
			body:   modified(func(r *createUserRequest) { r.Email = "nobody" }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check:  func(t *testing.T, e errorBody) { assert.Equal(t, "email", fieldRule(e, "email")) },
		},
		{
			name:   "missing full name",
			body:   modified(func(r *createUserRequest) { r.FullName = "" }),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check:  func(t *testing.T, e errorBody) { assert.Equal(t, "required", fieldRule(e, "full_name")) },
		},
		{
			name:   "duplicate email",
			body:   valid,
			status: http.StatusConflict,
			code:   "CONFLICT",
			check: func(t *testing.T, e errorBody) {
				assert.Equal(t, "user with this email already exists", e.Message)
				assert.Equal(t, map[string]any{"resource": "user", "field": "email", "value": valid.Email}, e.Details)
			},
		},
		{
			name:   "duplicate email in another case",
			body:   modified(func(r *createUserRequest) { r.Email = strings.ToUpper(valid.Email) }),
			status: http.StatusConflict,
			code:   "CONFLICT",
			check:  func(t *testing.T, e errorBody) { assert.Equal(t, valid.Email, e.Details["value"]) },
		},
		{
			name:   "body is not a JSON object",
			body:   rawBody("[]"),
			status: http.StatusBadRequest,
			code:   "VALIDATION_ERROR",
			check: func(t *testing.T, e errorBody) {
				assert.Equal(t, "body must be a JSON object", e.Details["reason"])
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tc.check(t, requireError(t, c.do(t, http.MethodPost, "/api/v1/users", tc.body, admin), tc.status, tc.code))
		})
	}
}
