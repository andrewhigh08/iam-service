package handler

import (
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	testEmail    = "user@example.com"
	testPassword = "Secret123!"
)

func authRouter(f *authFixture) *gin.Engine {
	r := gin.New()
	r.POST("/auth/login", f.h.Login)
	r.POST("/auth/refresh", f.h.Refresh)
	r.POST("/auth/logout", f.h.Logout)
	r.POST("/api/v1/logout-all", authenticated, f.h.LogoutAll)
	return r
}

var issuedPair = &port.TokenPair{AccessToken: "access-token", RefreshToken: "refresh-token", ExpiresIn: 900}

func issuedLogin(roles []string) *port.LoginResult {
	return &port.LoginResult{
		Tokens: issuedPair,
		User:   &domain.User{ID: testUserID, Email: testEmail},
		Roles:  roles,
	}
}

func TestLogin_IssuesTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	pair := issuedPair
	f.auth.EXPECT().Login(gomock.Any(), testEmail, testPassword, testMeta).Return(issuedLogin([]string{"viewer", "analyst"}), nil)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", LoginRequest{Email: testEmail, Password: testPassword}))

	data := decodeSuccess[LoginResponse](t, rec, http.StatusOK)
	assert.Equal(t, pair.AccessToken, data.AccessToken)
	assert.Equal(t, pair.RefreshToken, data.RefreshToken)
	assert.Equal(t, "Bearer", data.TokenType)
	assert.Equal(t, int64(900), data.ExpiresIn)
	require.NotNil(t, data.User)
	assert.Equal(t, UserInfo{ID: testUserID, Email: testEmail, Roles: []string{"viewer", "analyst"}}, *data.User)
	assert.False(t, data.RequirePasswordChange)
	assert.Empty(t, data.Reason)
}

func TestLogin_RolesAreNeverNull(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().Login(gomock.Any(), testEmail, testPassword, testMeta).Return(issuedLogin(nil), nil)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", LoginRequest{Email: testEmail, Password: testPassword}))

	data := decodeSuccess[LoginResponse](t, rec, http.StatusOK)
	require.NotNil(t, data.User)
	assert.Empty(t, data.User.Roles)
	assert.Contains(t, rec.Body.String(), `"roles":[]`)
}

func TestLogin_RequiresAPasswordChange(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().Login(gomock.Any(), testEmail, testPassword, testMeta).
		Return(&port.LoginResult{RequirePasswordChange: true, Reason: port.ReasonTemporaryPassword}, nil)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", LoginRequest{Email: testEmail, Password: testPassword}))

	data := decodeSuccess[LoginResponse](t, rec, http.StatusOK)
	assert.True(t, data.RequirePasswordChange)
	assert.Equal(t, port.ReasonTemporaryPassword, data.Reason)
	assert.Empty(t, data.AccessToken)
	assert.Nil(t, data.User)
	assert.NotContains(t, rec.Body.String(), "token")
}

func TestLogin_RejectsInvalidBodies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       any
		wantFields map[string]any
		wantReason string
	}{
		{name: "missing password", body: LoginRequest{Email: testEmail}, wantFields: map[string]any{"password": "required"}},
		{name: "missing everything", body: map[string]any{}, wantFields: map[string]any{"email": "required", "password": "required"}},
		{name: "malformed email", body: LoginRequest{Email: "nope", Password: "x"}, wantFields: map[string]any{"email": "email"}},
		{name: "overlong email", body: LoginRequest{Email: overlongEmail, Password: "x"}, wantFields: map[string]any{"email": "max=254"}},
		{name: "wrong field type", body: `{"email":123,"password":"x"}`, wantFields: map[string]any{"email": "invalid type"}},
		{name: "not an object", body: `[1,2]`, wantReason: "body must be a JSON object"},
		{name: "malformed json", body: `{"email":`, wantReason: "body must be a JSON object"},
		{name: "empty body", body: "", wantReason: "body must be a JSON object"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)

			rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", tt.body))

			errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
			if tt.wantReason != "" {
				assert.Equal(t, tt.wantReason, errBody.Details["reason"])
				return
			}
			assert.Equal(t, tt.wantFields, validationFields(t, errBody))
		})
	}
}

func TestLogin_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantMessage string
		secret      string
	}{
		{"invalid credentials", apperror.Unauthorized("invalid credentials"), http.StatusUnauthorized, apperror.CodeUnauthorized, "invalid credentials", ""},
		{"locked account", apperror.Unauthorized("account temporarily locked"), http.StatusUnauthorized, apperror.CodeUnauthorized, "account temporarily locked", ""},
		{"store unavailable", apperror.ServiceUnavailable("login temporarily unavailable"), http.StatusServiceUnavailable, apperror.CodeServiceUnavailable, "login temporarily unavailable", ""},
		{"internal error hides its cause", apperror.Internal("database unavailable", errors.New("pq: connection refused")), http.StatusInternalServerError, apperror.CodeInternal, "database unavailable", "pq: connection refused"},
		{"plain error becomes a generic 500", errors.New("boom"), http.StatusInternalServerError, apperror.CodeInternal, "an unexpected error occurred", "boom"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			f.auth.EXPECT().Login(gomock.Any(), testEmail, testPassword, testMeta).Return(nil, tt.err)

			rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", LoginRequest{Email: testEmail, Password: testPassword}))

			assertError(t, rec, tt.wantStatus, tt.wantCode, tt.wantMessage)
			if tt.secret != "" {
				assert.NotContains(t, rec.Body.String(), tt.secret)
			}
		})
	}
}

func TestLogin_FailsWithoutTokensOrUser(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		result *port.LoginResult
	}{
		{"no token pair", &port.LoginResult{User: &domain.User{ID: testUserID}}},
		{"no user", &port.LoginResult{Tokens: issuedPair}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			f.auth.EXPECT().Login(gomock.Any(), testEmail, testPassword, testMeta).Return(tt.result, nil)

			rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/login", LoginRequest{Email: testEmail, Password: testPassword}))

			assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to issue tokens")
			assertErrorLogged(t, f.logs, "service returned no tokens or no user")
		})
	}
}

func TestRefresh_RotatesTheTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	pair := &port.TokenPair{AccessToken: "new-access", RefreshToken: "new-refresh", ExpiresIn: 900}
	f.auth.EXPECT().Refresh(gomock.Any(), "old-refresh", testMeta).Return(pair, nil)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/refresh", RefreshRequest{RefreshToken: "old-refresh"}))

	data := decodeSuccess[TokenPairResponse](t, rec, http.StatusOK)
	assert.Equal(t, TokenPairResponse{AccessToken: "new-access", RefreshToken: "new-refresh", TokenType: "Bearer", ExpiresIn: 900}, data)
}

func TestRefresh_RejectsAMissingToken(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/refresh", map[string]any{}))

	errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
	assert.Equal(t, map[string]any{"refresh_token": "required"}, validationFields(t, errBody))
}

func TestRefresh_MapsServiceErrors(t *testing.T) {
	t.Parallel()

	t.Run("unknown refresh token", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().Refresh(gomock.Any(), "stale", testMeta).Return(nil, apperror.Unauthorized("invalid refresh token"))

		rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/refresh", RefreshRequest{RefreshToken: "stale"}))

		assertError(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, "invalid refresh token")
	})

	t.Run("no pair and no error", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().Refresh(gomock.Any(), "odd", testMeta).Return(nil, nil)

		rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/refresh", RefreshRequest{RefreshToken: "odd"}))

		assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to issue tokens")
		assertErrorLogged(t, f.logs, "service returned no token pair")
	})
}

func TestLogout_PicksTheAccessTokenFromTheBodyOrTheHeader(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		body          LogoutRequest
		authorization string
		wantAccess    string
	}{
		{"body token wins over the header", LogoutRequest{RefreshToken: "refresh", AccessToken: "body-access"}, "Bearer header-access", "body-access"},
		{"header token when the body has none", LogoutRequest{RefreshToken: "refresh"}, "Bearer header-access", "header-access"},
		{"no access token at all", LogoutRequest{RefreshToken: "refresh"}, "", ""},
		{"malformed header is ignored", LogoutRequest{RefreshToken: "refresh"}, "Basic abc", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			f.auth.EXPECT().Logout(gomock.Any(), "refresh", tt.wantAccess, testMeta).Return(nil)
			req := newRequest(t, http.MethodPost, "/auth/logout", tt.body)
			if tt.authorization != "" {
				req.Header.Set("Authorization", tt.authorization)
			}

			rec := serve(authRouter(f), req)

			data := decodeSuccess[MessageResponse](t, rec, http.StatusOK)
			assert.Equal(t, "logged out", data.Message)
		})
	}
}

func TestLogout_RejectsAMissingRefreshToken(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/logout", LogoutRequest{AccessToken: "a"}))

	errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
	assert.Equal(t, map[string]any{"refresh_token": "required"}, validationFields(t, errBody))
}

func TestLogout_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().Logout(gomock.Any(), "refresh", "", testMeta).Return(apperror.Internal("session store unavailable", errors.New("dial tcp: refused")))

	rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/auth/logout", LogoutRequest{RefreshToken: "refresh"}))

	assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "session store unavailable")
	assert.NotContains(t, rec.Body.String(), "dial tcp")
}

func TestLogoutAll(t *testing.T) {
	t.Parallel()

	t.Run("ends every session of the caller", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().LogoutAll(gomock.Any(), testUserID, testMeta).Return(nil)

		rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/api/v1/logout-all", nil))

		data := decodeSuccess[MessageResponse](t, rec, http.StatusOK)
		assert.Equal(t, "logged out from all sessions", data.Message)
	})

	t.Run("maps service errors", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().LogoutAll(gomock.Any(), testUserID, testMeta).Return(apperror.ServiceUnavailable("revocation store unavailable"))

		rec := serve(authRouter(f), newRequest(t, http.MethodPost, "/api/v1/logout-all", nil))

		assertError(t, rec, http.StatusServiceUnavailable, apperror.CodeServiceUnavailable, "revocation store unavailable")
	})
}
