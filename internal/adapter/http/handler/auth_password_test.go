package handler

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	oldPassword = "Old-Secret-1"
	newPassword = "New-Secret-2"
)

// passwordRouter mounts the authenticated and the forced password change endpoints of f.
func passwordRouter(f *authFixture) *gin.Engine {
	r := gin.New()
	r.POST("/api/v1/change-password", authenticated, f.h.ChangePassword)
	r.POST("/auth/change-password", f.h.ChangeRequiredPassword)
	return r
}

// freshPair is the pair the services hand out after a password change.
var freshPair = &port.TokenPair{AccessToken: "fresh-access", RefreshToken: "fresh-refresh", ExpiresIn: 900}

// wantFreshPair is freshPair as the handlers render it.
var wantFreshPair = TokenPairResponse{AccessToken: "fresh-access", RefreshToken: "fresh-refresh", TokenType: "Bearer", ExpiresIn: 900}

func TestChangePassword_ReturnsAFreshPair(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().ChangePassword(gomock.Any(), testUserID, oldPassword, newPassword, testMeta).Return(freshPair, nil)
	body := ChangePasswordRequest{OldPassword: oldPassword, NewPassword: newPassword}

	rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/api/v1/change-password", body))

	assert.Equal(t, wantFreshPair, decodeSuccess[TokenPairResponse](t, rec, http.StatusOK))
}

func TestChangePassword_RejectsInvalidBodies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       any
		wantFields map[string]any
	}{
		{"missing both", map[string]any{}, map[string]any{"old_password": "required", "new_password": "required"}},
		{"missing new password", ChangePasswordRequest{OldPassword: oldPassword}, map[string]any{"new_password": "required"}},
		{"missing old password", ChangePasswordRequest{NewPassword: newPassword}, map[string]any{"old_password": "required"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)

			rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/api/v1/change-password", tt.body))

			errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
			assert.Equal(t, tt.wantFields, validationFields(t, errBody))
		})
	}
}

func TestChangePassword_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	body := ChangePasswordRequest{OldPassword: oldPassword, NewPassword: newPassword}

	t.Run("wrong current password", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().ChangePassword(gomock.Any(), testUserID, oldPassword, newPassword, testMeta).
			Return(nil, apperror.Unauthorized("invalid credentials"))

		rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/api/v1/change-password", body))

		assertError(t, rec, http.StatusUnauthorized, apperror.CodeUnauthorized, "invalid credentials")
	})

	t.Run("weak new password", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().ChangePassword(gomock.Any(), testUserID, oldPassword, newPassword, testMeta).
			Return(nil, apperror.ValidationError("password does not meet the policy", map[string]any{"violations": []string{"uppercase"}}))

		rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/api/v1/change-password", body))

		errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "password does not meet the policy")
		assert.Equal(t, []any{"uppercase"}, errBody.Details["violations"])
	})

	t.Run("no pair and no error", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().ChangePassword(gomock.Any(), testUserID, oldPassword, newPassword, testMeta).Return(nil, nil)

		rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/api/v1/change-password", body))

		assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to issue tokens")
		assertErrorLogged(t, f.logs, "service returned no token pair")
	})
}

func TestChangeRequiredPassword_ReturnsAFreshPair(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().ChangeRequiredPassword(gomock.Any(), testEmail, oldPassword, newPassword, testMeta).Return(freshPair, nil)
	body := ChangeRequiredPasswordRequest{Email: testEmail, OldPassword: oldPassword, NewPassword: newPassword}

	rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/auth/change-password", body))

	assert.Equal(t, wantFreshPair, decodeSuccess[TokenPairResponse](t, rec, http.StatusOK))
}

func TestChangeRequiredPassword_RejectsInvalidBodies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		body       any
		wantFields map[string]any
	}{
		{"missing email", ChangeRequiredPasswordRequest{OldPassword: oldPassword, NewPassword: newPassword}, map[string]any{"email": "required"}},
		{"malformed email", ChangeRequiredPasswordRequest{Email: "nope", OldPassword: oldPassword, NewPassword: newPassword}, map[string]any{"email": "email"}},
		{"missing passwords", ChangeRequiredPasswordRequest{Email: testEmail}, map[string]any{"old_password": "required", "new_password": "required"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)

			rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/auth/change-password", tt.body))

			errBody := assertError(t, rec, http.StatusBadRequest, apperror.CodeValidation, "invalid request body")
			assert.Equal(t, tt.wantFields, validationFields(t, errBody))
		})
	}
}

func TestChangeRequiredPassword_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		err         error
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{"change not required", apperror.BadRequest("password change not required"), http.StatusBadRequest, apperror.CodeBadRequest, "password change not required"},
		{"wrong current password", apperror.Unauthorized("invalid credentials"), http.StatusUnauthorized, apperror.CodeUnauthorized, "invalid credentials"},
		{"locked account", apperror.Unauthorized("account temporarily locked"), http.StatusUnauthorized, apperror.CodeUnauthorized, "account temporarily locked"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			f.auth.EXPECT().ChangeRequiredPassword(gomock.Any(), testEmail, oldPassword, newPassword, testMeta).Return(nil, tt.err)
			body := ChangeRequiredPasswordRequest{Email: testEmail, OldPassword: oldPassword, NewPassword: newPassword}

			rec := serve(passwordRouter(f), newRequest(t, http.MethodPost, "/auth/change-password", body))

			assertError(t, rec, tt.wantStatus, tt.wantCode, tt.wantMessage)
		})
	}
}
