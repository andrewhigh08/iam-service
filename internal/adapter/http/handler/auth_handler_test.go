package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

func setupAuthTest(t *testing.T) (*AuthHandler, *mocks.MockAuthService, *mocks.MockAuthorizationService, *gin.Engine) {
	ctrl := gomock.NewController(t)
	mockAuth := mocks.NewMockAuthService(ctrl)
	mockAuthz := mocks.NewMockAuthorizationService(ctrl)
	log := logger.New(logger.Config{Level: "debug", Format: "text"})

	handler := NewAuthHandler(mockAuth, mockAuthz, log)

	gin.SetMode(gin.TestMode)
	router := gin.New()

	return handler, mockAuth, mockAuthz, router
}

func TestAuthHandler_Login_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	// Setup expectations
	mockAuth.EXPECT().
		Login(gomock.Any(), "test@example.com", "password123").
		Return(&port.TokenPair{AccessToken: "jwt-token-123", RefreshToken: "refresh-token-123"}, false, nil)

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "jwt-token-123").
		Return(&port.Claims{
			UserID: 1,
			Email:  "test@example.com",
			Roles:  []string{"user"},
		}, nil)

	// Make request
	body := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "jwt-token-123", data["access_token"])
	assert.Equal(t, "refresh-token-123", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.NotNil(t, data["user"])
}

func TestAuthHandler_Login_OTPFlow(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	// Setup expectations for OTP flow
	mockAuth.EXPECT().
		Login(gomock.Any(), "test@example.com", "otp123").
		Return((*port.TokenPair)(nil), true, nil)

	mockAuth.EXPECT().
		GetUserByEmail(gomock.Any(), "test@example.com").
		Return(&domain.User{ID: 42, Email: "test@example.com"}, nil)

	// Make request
	body := `{"email":"test@example.com","password":"otp123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Assertions
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.True(t, data["require_password_change"].(bool))
	assert.Equal(t, float64(42), data["user_id"])
	assert.Contains(t, data["message"], "One-time password")
}

func TestAuthHandler_Login_InvalidRequest(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	tests := []struct {
		name string
		body string
	}{
		{"missing email", `{"password":"password123"}`},
		{"missing password", `{"email":"test@example.com"}`},
		{"invalid email format", `{"email":"invalid","password":"password123"}`},
		{"empty body", ``},
		{"invalid json", `{invalid}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)

			var resp map[string]interface{}
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.False(t, resp["success"].(bool))
		})
	}
}

func TestAuthHandler_Login_AuthError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	mockAuth.EXPECT().
		Login(gomock.Any(), "test@example.com", "wrongpassword").
		Return((*port.TokenPair)(nil), false, apperror.Unauthorized("invalid credentials"))

	body := `{"email":"test@example.com","password":"wrongpassword"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["success"].(bool))
	assert.NotNil(t, resp["error"])
}

func TestAuthHandler_Login_AccountLocked(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	mockAuth.EXPECT().
		Login(gomock.Any(), "locked@example.com", "password123").
		Return((*port.TokenPair)(nil), false, apperror.Unauthorized("account is temporarily locked due to too many failed login attempts"))

	body := `{"email":"locked@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["success"].(bool))

	errData := resp["error"].(map[string]interface{})
	assert.Contains(t, errData["message"], "temporarily locked")
}

func TestAuthHandler_Login_TokenValidationFails(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/login", handler.Login)

	mockAuth.EXPECT().
		Login(gomock.Any(), "test@example.com", "password123").
		Return(&port.TokenPair{AccessToken: "jwt-token-123", RefreshToken: "refresh-token-123"}, false, nil)

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "jwt-token-123").
		Return(nil, errors.New("token validation failed"))

	body := `{"email":"test@example.com","password":"password123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_ChangePassword_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/api/v1/change-password", func(c *gin.Context) {
		c.Set("user_id", int64(1))
		handler.ChangePassword(c)
	})

	mockAuth.EXPECT().
		ChangePassword(gomock.Any(), int64(1), "oldpassword", "NewSecureP@ss123").
		Return(nil)

	body := `{"old_password":"oldpassword","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))
}

func TestAuthHandler_ChangePassword_InvalidRequest(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/api/v1/change-password", func(c *gin.Context) {
		c.Set("user_id", int64(1))
		handler.ChangePassword(c)
	})

	tests := []struct {
		name string
		body string
	}{
		{"missing old_password", `{"new_password":"NewSecureP@ss123"}`},
		{"missing new_password", `{"old_password":"oldpassword"}`},
		{"new_password too short", `{"old_password":"oldpassword","new_password":"short"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/change-password", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_ChangePassword_ServiceError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/api/v1/change-password", func(c *gin.Context) {
		c.Set("user_id", int64(1))
		handler.ChangePassword(c)
	})

	mockAuth.EXPECT().
		ChangePassword(gomock.Any(), int64(1), "wrongold", "NewSecureP@ss123").
		Return(apperror.Unauthorized("incorrect current password"))

	body := `{"old_password":"wrongold","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_ChangePassword_WeakPassword(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/api/v1/change-password", func(c *gin.Context) {
		c.Set("user_id", int64(1))
		handler.ChangePassword(c)
	})

	// Test weak password (no special character)
	body := `{"old_password":"oldpassword","new_password":"WeakPass123"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/change-password", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["success"].(bool))

	// Check that error contains validation details
	errData := resp["error"].(map[string]interface{})
	details := errData["details"].(map[string]interface{})
	errors := details["errors"].([]interface{})
	assert.NotEmpty(t, errors)
}

func TestAuthHandler_FirstTimePasswordChange_Success(t *testing.T) {
	handler, mockAuth, mockAuthz, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	mockAuth.EXPECT().
		FirstTimePasswordChange(gomock.Any(), int64(42), "otp123", "NewSecureP@ss123").
		Return(nil)

	mockAuth.EXPECT().
		GenerateTokenForUser(gomock.Any(), int64(42)).
		Return(&port.TokenPair{AccessToken: "new-jwt-token", RefreshToken: "new-refresh-token"}, nil)

	mockAuthz.EXPECT().
		GetUserRoles(gomock.Any(), int64(42)).
		Return([]string{"user"}, nil)

	body := `{"user_id":42,"old_password":"otp123","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))

	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "new-jwt-token", data["access_token"])
	assert.Equal(t, "new-refresh-token", data["refresh_token"])
	assert.Equal(t, "Bearer", data["token_type"])
	assert.Contains(t, data["message"], "Password changed successfully")
}

func TestAuthHandler_FirstTimePasswordChange_WeakPassword(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	// Test with weak password (common password)
	body := `{"user_id":42,"old_password":"otp123","new_password":"password"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["success"].(bool))
}

func TestAuthHandler_FirstTimePasswordChange_InvalidRequest(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	tests := []struct {
		name string
		body string
	}{
		{"missing user_id", `{"old_password":"otp123","new_password":"NewSecureP@ss123"}`},
		{"missing old_password", `{"user_id":42,"new_password":"NewSecureP@ss123"}`},
		{"missing new_password", `{"user_id":42,"old_password":"otp123"}`},
		{"new_password too short", `{"user_id":42,"old_password":"otp123","new_password":"short"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_FirstTimePasswordChange_PasswordChangeError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	mockAuth.EXPECT().
		FirstTimePasswordChange(gomock.Any(), int64(42), "wrongotp", "NewSecureP@ss123").
		Return(apperror.Unauthorized("invalid OTP password"))

	body := `{"user_id":42,"old_password":"wrongotp","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_FirstTimePasswordChange_TokenGenerationError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	mockAuth.EXPECT().
		FirstTimePasswordChange(gomock.Any(), int64(42), "otp123", "NewSecureP@ss123").
		Return(nil)

	mockAuth.EXPECT().
		GenerateTokenForUser(gomock.Any(), int64(42)).
		Return((*port.TokenPair)(nil), apperror.Internal("token generation failed", nil))

	body := `{"user_id":42,"old_password":"otp123","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_FirstTimePasswordChange_GetRolesError(t *testing.T) {
	handler, mockAuth, mockAuthz, router := setupAuthTest(t)

	router.POST("/auth/first-time-password-change", handler.FirstTimePasswordChange)

	mockAuth.EXPECT().
		FirstTimePasswordChange(gomock.Any(), int64(42), "otp123", "NewSecureP@ss123").
		Return(nil)

	mockAuth.EXPECT().
		GenerateTokenForUser(gomock.Any(), int64(42)).
		Return(&port.TokenPair{AccessToken: "new-jwt-token", RefreshToken: "new-refresh-token"}, nil)

	mockAuthz.EXPECT().
		GetUserRoles(gomock.Any(), int64(42)).
		Return(nil, errors.New("database error"))

	body := `{"user_id":42,"old_password":"otp123","new_password":"NewSecureP@ss123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/first-time-password-change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_AuthMiddleware_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		userID := c.GetInt64("user_id")
		email := c.GetString("email")
		c.JSON(http.StatusOK, gin.H{"user_id": userID, "email": email})
	})

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "valid-token").
		Return(&port.Claims{
			UserID: 123,
			Email:  "test@example.com",
			Roles:  []string{"user"},
		}, nil)

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, float64(123), resp["user_id"])
	assert.Equal(t, "test@example.com", resp["email"])
}

func TestAuthHandler_AuthMiddleware_MissingHeader(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_AuthMiddleware_InvalidFormat(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	tests := []struct {
		name   string
		header string
	}{
		{"no Bearer prefix", "token-without-bearer"},
		{"Basic auth", "Basic dXNlcjpwYXNz"},
		{"only Bearer", "Bearer"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			req.Header.Set("Authorization", tt.header)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

func TestAuthHandler_AuthMiddleware_EmptyToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	// "Bearer " with trailing space passes format check but token is empty
	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "").
		Return(nil, errors.New("empty token"))

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer ")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_AuthMiddleware_InvalidToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "invalid-token").
		Return(nil, errors.New("token expired"))

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer invalid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RBACMiddleware_Success(t *testing.T) {
	handler, _, mockAuthz, router := setupAuthTest(t)

	router.GET("/users", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.RBACMiddleware("users", "read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "access granted"})
	})

	mockAuthz.EXPECT().
		CheckAccess(gomock.Any(), int64(123), "users", "read").
		Return(true, nil)

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_RBACMiddleware_Forbidden(t *testing.T) {
	handler, _, mockAuthz, router := setupAuthTest(t)

	router.GET("/admin", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.RBACMiddleware("admin", "access"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	mockAuthz.EXPECT().
		CheckAccess(gomock.Any(), int64(123), "admin", "access").
		Return(false, nil)

	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestAuthHandler_RBACMiddleware_NoUserID(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.GET("/users", handler.RBACMiddleware("users", "read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestAuthHandler_RBACMiddleware_CheckAccessError(t *testing.T) {
	handler, _, mockAuthz, router := setupAuthTest(t)

	router.GET("/users", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.RBACMiddleware("users", "read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	mockAuthz.EXPECT().
		CheckAccess(gomock.Any(), int64(123), "users", "read").
		Return(false, errors.New("database error"))

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestAuthHandler_RBACMiddleware_InvalidUserIDType(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.GET("/users", func(c *gin.Context) {
		c.Set("user_id", "not-an-int64") // Wrong type
		c.Next()
	}, handler.RBACMiddleware("users", "read"), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	req := httptest.NewRequest(http.MethodGet, "/users", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==================== Logout Tests ====================

func TestAuthHandler_Logout_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/logout", handler.Logout)

	mockAuth.EXPECT().
		Logout(gomock.Any(), "refresh-token-123", "").
		Return(nil)

	body := `{"refresh_token":"refresh-token-123"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.Contains(t, data["message"], "Logged out successfully")
}

func TestAuthHandler_Logout_WithAccessToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/logout", handler.Logout)

	mockAuth.EXPECT().
		Logout(gomock.Any(), "refresh-token-123", "access-token-456").
		Return(nil)

	body := `{"refresh_token":"refresh-token-123","access_token":"access-token-456"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))
}

func TestAuthHandler_Logout_InvalidRequest(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/auth/logout", handler.Logout)

	tests := []struct {
		name string
		body string
	}{
		{"missing refresh_token", `{"access_token":"token"}`},
		{"empty body", ``},
		{"invalid json", `{invalid}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_Logout_ServiceError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/logout", handler.Logout)

	mockAuth.EXPECT().
		Logout(gomock.Any(), "invalid-token", "").
		Return(apperror.Internal("failed to logout", nil))

	body := `{"refresh_token":"invalid-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/logout", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==================== LogoutAll Tests ====================

func TestAuthHandler_LogoutAll_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/api/v1/logout-all", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.LogoutAll)

	mockAuth.EXPECT().
		LogoutAll(gomock.Any(), int64(123), "").
		Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout-all", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.Contains(t, data["message"], "Logged out from all devices")
}

func TestAuthHandler_LogoutAll_WithAccessToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/api/v1/logout-all", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.LogoutAll)

	mockAuth.EXPECT().
		LogoutAll(gomock.Any(), int64(123), "current-access-token").
		Return(nil)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout-all", http.NoBody)
	req.Header.Set("Authorization", "Bearer current-access-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_LogoutAll_ServiceError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/api/v1/logout-all", func(c *gin.Context) {
		c.Set("user_id", int64(123))
		c.Next()
	}, handler.LogoutAll)

	mockAuth.EXPECT().
		LogoutAll(gomock.Any(), int64(123), "").
		Return(apperror.Internal("failed to logout", nil))

	req := httptest.NewRequest(http.MethodPost, "/api/v1/logout-all", http.NoBody)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ==================== RefreshToken Tests ====================

func TestAuthHandler_RefreshToken_Success(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/refresh", handler.RefreshToken)

	mockAuth.EXPECT().
		RefreshToken(gomock.Any(), "valid-refresh-token").
		Return("new-access-token-123", nil)

	body := `{"refresh_token":"valid-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp["success"].(bool))
	data := resp["data"].(map[string]interface{})
	assert.Equal(t, "new-access-token-123", data["access_token"])
	assert.Equal(t, "Bearer", data["token_type"])
}

func TestAuthHandler_RefreshToken_InvalidRequest(t *testing.T) {
	handler, _, _, router := setupAuthTest(t)

	router.POST("/auth/refresh", handler.RefreshToken)

	tests := []struct {
		name string
		body string
	}{
		{"missing refresh_token", `{}`},
		{"empty body", ``},
		{"invalid json", `{invalid}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestAuthHandler_RefreshToken_InvalidToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.POST("/auth/refresh", handler.RefreshToken)

	mockAuth.EXPECT().
		RefreshToken(gomock.Any(), "expired-refresh-token").
		Return("", apperror.Unauthorized("invalid or expired refresh token"))

	body := `{"refresh_token":"expired-refresh-token"}`
	req := httptest.NewRequest(http.MethodPost, "/auth/refresh", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ==================== AuthMiddleware Blacklist Tests ====================

func TestAuthHandler_AuthMiddleware_BlacklistedToken(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"message": "should not reach here"})
	})

	// Token is valid but blacklisted
	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "blacklisted-token").
		Return(&port.Claims{
			UserID:           123,
			Email:            "test@example.com",
			Roles:            []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{ID: "jti-123"},
		}, nil)

	mockAuth.EXPECT().
		IsTokenBlacklisted(gomock.Any(), "jti-123").
		Return(true, nil)

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer blacklisted-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.False(t, resp["success"].(bool))
}

func TestAuthHandler_AuthMiddleware_NotBlacklisted(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		userID := c.GetInt64("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "valid-token").
		Return(&port.Claims{
			UserID:           123,
			Email:            "test@example.com",
			Roles:            []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{ID: "jti-456"},
		}, nil)

	mockAuth.EXPECT().
		IsTokenBlacklisted(gomock.Any(), "jti-456").
		Return(false, nil)

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_AuthMiddleware_BlacklistCheckError(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		userID := c.GetInt64("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "valid-token").
		Return(&port.Claims{
			UserID:           123,
			Email:            "test@example.com",
			Roles:            []string{"user"},
			RegisteredClaims: jwt.RegisteredClaims{ID: "jti-789"},
		}, nil)

	// Blacklist check fails but we continue (fail-open)
	mockAuth.EXPECT().
		IsTokenBlacklisted(gomock.Any(), "jti-789").
		Return(false, errors.New("redis connection error"))

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer valid-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Should still succeed (fail-open for availability)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAuthHandler_AuthMiddleware_TokenWithoutJTI(t *testing.T) {
	handler, mockAuth, _, router := setupAuthTest(t)

	router.GET("/protected", handler.AuthMiddleware(), func(c *gin.Context) {
		userID := c.GetInt64("user_id")
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	// Token without JTI (legacy token)
	mockAuth.EXPECT().
		ValidateToken(gomock.Any(), "legacy-token").
		Return(&port.Claims{
			UserID: 123,
			Email:  "test@example.com",
			Roles:  []string{"user"},
			// No JTI set (ID is empty)
		}, nil)

	// IsTokenBlacklisted should NOT be called when JTI is empty

	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer legacy-token")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
