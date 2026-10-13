package handler

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// identity is what a handler behind AuthMiddleware observes about the caller.
type identity struct {
	called    bool
	userID    int64
	sessionID string
	email     string
	roles     []string
	ctxUserID int64
}

// capture records the caller identity stored in the gin and request contexts.
func (id *identity) capture(c *gin.Context) {
	id.called = true
	id.userID = c.GetInt64(ContextKeyUserID)
	id.sessionID = c.GetString(ContextKeySessionID)
	id.email = c.GetString(ContextKeyEmail)
	id.roles = c.GetStringSlice(ContextKeyRoles)
	id.ctxUserID = logger.UserIDFromContext(c.Request.Context())
	c.String(http.StatusOK, "ok")
}

// protectedRouter serves GET /me behind AuthMiddleware and records the identity it sees.
func protectedRouter(f *authFixture, id *identity) *gin.Engine {
	r := gin.New()
	r.GET("/me", f.h.AuthMiddleware(), id.capture)
	return r
}

func TestAuthMiddleware_RejectsRequestsWithoutAValidBearerHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authorization string
		wantMessage   string
	}{
		{"missing header", "", "missing authorization header"},
		{"wrong scheme", "Basic dXNlcjpwYXNz", "invalid authorization header format"},
		{"scheme without token", "Bearer", "invalid authorization header format"},
		{"scheme with a blank token", "Bearer   ", "invalid authorization header format"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			var id identity
			req := newRequest(t, http.MethodGet, "/me", nil)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			rec := serve(protectedRouter(f, &id), req)

			assertError(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, tt.wantMessage)
			assert.False(t, id.called, "the handler must not run")
		})
	}
}

func TestAuthMiddleware_RejectsInvalidTokens(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
	}{
		{"expired token", apperror.Unauthorized("token has expired")},
		{"revoked token", apperror.Unauthorized("token has been revoked")},
		{"unexpected parse failure", errors.New("key not found")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			f.auth.EXPECT().ValidateAccessToken(gomock.Any(), "bad-token").Return(nil, tt.err)
			var id identity
			req := newRequest(t, http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", "Bearer bad-token")

			rec := serve(protectedRouter(f, &id), req)

			assertError(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, "invalid or expired token")
			assert.NotContains(t, rec.Body.String(), tt.err.Error(), "the cause is never exposed")
			assert.False(t, id.called)
		})
	}
}

func TestAuthMiddleware_FailsClosedWhenValidationIsUnavailable(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().ValidateAccessToken(gomock.Any(), "some-token").
		Return(nil, apperror.ServiceUnavailable("token validation unavailable"))
	var id identity
	req := newRequest(t, http.MethodGet, "/me", nil)
	req.Header.Set("Authorization", "Bearer some-token")

	rec := serve(protectedRouter(f, &id), req)

	assertError(t, rec, http.StatusServiceUnavailable, apperror.CodeServiceUnavailable, "token validation unavailable")
	assert.False(t, id.called)
	assertErrorLogged(t, f.logs, "access token validation unavailable")
}

func TestAuthMiddleware_StoresTheCallerIdentity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authorization string
	}{
		{"canonical scheme", "Bearer good-token"},
		{"lower-case scheme", "bearer good-token"},
		{"extra spaces around the token", "Bearer   good-token  "},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			claims := &port.Claims{UserID: testUserID, Email: testEmail, Roles: []string{"admin"}, SessionID: testSessionID}
			f.auth.EXPECT().ValidateAccessToken(gomock.Any(), "good-token").Return(claims, nil)
			var id identity
			req := newRequest(t, http.MethodGet, "/me", nil)
			req.Header.Set("Authorization", tt.authorization)

			rec := serve(protectedRouter(f, &id), req)

			require.Equal(t, http.StatusOK, rec.Code, "body: %s", rec.Body.String())
			assert.Equal(t, "ok", rec.Body.String())
			assert.True(t, id.called)
			assert.Equal(t, testUserID, id.userID)
			assert.Equal(t, testSessionID, id.sessionID)
			assert.Equal(t, testEmail, id.email)
			assert.Equal(t, []string{"admin"}, id.roles)
			assert.Equal(t, testUserID, id.ctxUserID, "the request context carries the user id for logging")
		})
	}
}

// rbacRouter serves GET /users behind RBACMiddleware(users, read), optionally pre-authenticated.
func rbacRouter(f *authFixture, withUser bool, called *bool) *gin.Engine {
	r := gin.New()
	handlers := []gin.HandlerFunc{}
	if withUser {
		handlers = append(handlers, authenticated)
	}
	handlers = append(handlers, f.h.RBACMiddleware("users", "read"), func(c *gin.Context) {
		*called = true
		c.String(http.StatusOK, "ok")
	})
	r.GET("/users", handlers...)
	return r
}

func TestRBACMiddleware(t *testing.T) {
	t.Parallel()

	t.Run("rejects an unauthenticated request", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		var called bool

		rec := serve(rbacRouter(f, false, &called), newRequest(t, http.MethodGet, "/users", nil))

		assertError(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, "authentication required")
		assert.False(t, called)
	})

	t.Run("fails when the check cannot be made", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.authz.EXPECT().CheckAccess(gomock.Any(), testUserID, "users", "read").Return(false, errors.New("enforcer down"))
		var called bool

		rec := serve(rbacRouter(f, true, &called), newRequest(t, http.MethodGet, "/users", nil))

		assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "authorization check failed")
		assert.NotContains(t, rec.Body.String(), "enforcer down")
		assert.False(t, called)
		assertErrorLogged(t, f.logs, "authorization check failed")
	})

	t.Run("forbids a denied action", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.authz.EXPECT().CheckAccess(gomock.Any(), testUserID, "users", "read").Return(false, nil)
		var called bool

		rec := serve(rbacRouter(f, true, &called), newRequest(t, http.MethodGet, "/users", nil))

		assertError(t, rec, http.StatusForbidden, apperror.CodeForbidden, "insufficient permissions")
		assert.False(t, called)
	})

	t.Run("lets an allowed action through", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.authz.EXPECT().CheckAccess(gomock.Any(), testUserID, "users", "read").Return(true, nil)
		var called bool

		rec := serve(rbacRouter(f, true, &called), newRequest(t, http.MethodGet, "/users", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
		assert.True(t, called)
	})
}

func TestIsServiceUnavailable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"plain error", errors.New("boom"), false},
		{"other app error", apperror.Unauthorized(""), false},
		{"service unavailable", apperror.ServiceUnavailable("down"), true},
		{"wrapped service unavailable", fmt.Errorf("validate: %w", apperror.ServiceUnavailable("down")), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isServiceUnavailable(tt.err))
		})
	}
}
