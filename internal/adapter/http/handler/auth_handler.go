// Package handler provides HTTP request handlers for the IAM service.
package handler

import (
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// AuthHandler handles authentication-related HTTP requests.
//
// Provides endpoints for login, password change, and token validation.
type AuthHandler struct {
	authService  port.AuthService          // Authentication service
	authzService port.AuthorizationService // Authorization service
	logger       *logger.Logger            // Logger instance
}

// NewAuthHandler creates a new AuthHandler instance.
func NewAuthHandler(
	authService port.AuthService,
	authzService port.AuthorizationService,
	log *logger.Logger,
) *AuthHandler {
	return &AuthHandler{
		authService:  authService,
		authzService: authzService,
		logger:       log.WithComponent("auth_handler"),
	}
}

// LoginRequest represents the login request body.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"` // User email
	Password string `json:"password" binding:"required"`    // User password
}

// LoginResponse represents a successful login response.
type LoginResponse struct {
	AccessToken  string    `json:"access_token,omitempty"`  // JWT access token
	RefreshToken string    `json:"refresh_token,omitempty"` // Refresh token for obtaining new access tokens
	TokenType    string    `json:"token_type,omitempty"`    // Token type (Bearer)
	User         *UserInfo `json:"user,omitempty"`          // User information
	// For OTP flow
	RequirePasswordChange bool   `json:"require_password_change,omitempty"` // OTP password change required
	UserID                int64  `json:"user_id,omitempty"`                 // User ID for OTP flow
	Message               string `json:"message,omitempty"`                 // Additional message
}

// UserInfo represents user information in responses.
type UserInfo struct {
	ID    int64    `json:"id"`    // User ID
	Email string   `json:"email"` // User email
	Roles []string `json:"roles"` // User roles
}

// Login handles POST /auth/login endpoint.
// @Summary User login
// @Description Authenticate user and get JWT tokens
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Login credentials"
// @Success 200 {object} response.APIResponse{data=LoginResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	tokens, isOTP, err := h.authService.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Handle one-time password flow
	if isOTP {
		// Get user to return user ID
		user, getUserErr := h.authService.GetUserByEmail(c.Request.Context(), req.Email)
		var userID int64
		if getUserErr == nil && user != nil {
			userID = user.ID
		}
		response.Success(c, LoginResponse{
			RequirePasswordChange: true,
			UserID:                userID,
			Message:               "One-time password detected. Please change your password.",
		})
		return
	}

	// Get user info for response
	claims, validateErr := h.authService.ValidateToken(c.Request.Context(), tokens.AccessToken)
	if validateErr != nil || claims == nil {
		response.InternalError(c, "failed to parse token")
		return
	}

	response.Success(c, LoginResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    "Bearer",
		User: &UserInfo{
			ID:    claims.UserID,
			Email: claims.Email,
			Roles: claims.Roles,
		},
	})
}

// ChangePasswordRequest represents the change password request body.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`       // Current password
	NewPassword string `json:"new_password" binding:"required,min=8"` // New password (min 8 chars)
}

// ChangePassword handles POST /api/v1/change-password.
// @Summary Change password
// @Description Change password for authenticated user
// @Tags auth
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ChangePasswordRequest true "Password change data"
// @Success 200 {object} response.APIResponse
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req domain.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	// Validate password complexity
	validationResult := validator.ValidatePasswordDefault(req.NewPassword)
	if !validationResult.Valid {
		response.ValidationError(c, "password does not meet complexity requirements", map[string]interface{}{
			"errors":   validationResult.Errors,
			"strength": validationResult.Strength.String(),
		})
		return
	}

	userID := c.GetInt64("user_id")
	if err := h.authService.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Password changed successfully"})
}

// FirstTimePasswordChangeRequest represents the first-time password change request.
type FirstTimePasswordChangeRequest struct {
	UserID      int64  `json:"user_id" binding:"required"`            // User ID
	OldPassword string `json:"old_password" binding:"required"`       // OTP password
	NewPassword string `json:"new_password" binding:"required,min=8"` // New permanent password
}

// FirstTimePasswordChangeResponse represents the response after first-time password change.
type FirstTimePasswordChangeResponse struct {
	Message      string   `json:"message"`       // Success message
	AccessToken  string   `json:"access_token"`  // JWT access token
	RefreshToken string   `json:"refresh_token"` // Refresh token
	TokenType    string   `json:"token_type"`    // Token type
	Roles        []string `json:"roles"`         // User roles
}

// FirstTimePasswordChange handles POST /auth/first-time-password-change.
// @Summary First-time password change
// @Description Change one-time password to permanent password
// @Tags auth
// @Accept json
// @Produce json
// @Param request body FirstTimePasswordChangeRequest true "Password change data"
// @Success 200 {object} response.APIResponse{data=FirstTimePasswordChangeResponse}
// @Failure 400 {object} response.APIResponse
// @Router /auth/first-time-password-change [post]
func (h *AuthHandler) FirstTimePasswordChange(c *gin.Context) {
	var req domain.FirstTimePasswordChangeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	// Validate password complexity
	validationResult := validator.ValidatePasswordDefault(req.NewPassword)
	if !validationResult.Valid {
		response.ValidationError(c, "password does not meet complexity requirements", map[string]interface{}{
			"errors":   validationResult.Errors,
			"strength": validationResult.Strength.String(),
		})
		return
	}

	if err := h.authService.FirstTimePasswordChange(c.Request.Context(), req.UserID, req.OldPassword, req.NewPassword); err != nil {
		response.Error(c, err)
		return
	}

	// Generate token pair for the user
	tokens, err := h.authService.GenerateTokenForUser(c.Request.Context(), req.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Get user roles
	roles, err := h.authzService.GetUserRoles(c.Request.Context(), req.UserID)
	if err != nil {
		response.InternalError(c, "failed to fetch roles")
		return
	}

	response.Success(c, FirstTimePasswordChangeResponse{
		Message:      "Password changed successfully",
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
		TokenType:    "Bearer",
		Roles:        roles,
	})
}

// RefreshTokenRequest represents the refresh token request body.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // Refresh token
}

// RefreshTokenResponse represents the refresh token response.
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"` // New access token
	TokenType   string `json:"token_type"`   // Token type (Bearer)
}

// RefreshToken handles POST /auth/refresh endpoint.
// @Summary Refresh access token
// @Description Get new access token using refresh token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshTokenRequest true "Refresh token"
// @Success 200 {object} response.APIResponse{data=RefreshTokenResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	accessToken, err := h.authService.RefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, RefreshTokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
	})
}

// LogoutRequest represents the logout request body.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // Refresh token to invalidate
	AccessToken  string `json:"access_token,omitempty"`           // Access token to blacklist (optional)
}

// Logout handles POST /auth/logout endpoint.
// @Summary Logout user
// @Description Invalidate refresh token and optionally blacklist access token
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Tokens to invalidate"
// @Success 200 {object} response.APIResponse
// @Failure 400 {object} response.APIResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.ValidationError(c, "invalid request body", map[string]interface{}{
			"details": err.Error(),
		})
		return
	}

	if err := h.authService.Logout(c.Request.Context(), req.RefreshToken, req.AccessToken); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Logged out successfully"})
}

// LogoutAll handles POST /api/v1/logout-all endpoint.
// @Summary Logout from all devices
// @Description Invalidate all refresh tokens for the user and blacklist current access token
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	userID := c.GetInt64("user_id")

	// Extract current access token from Authorization header
	accessToken := ""
	authHeader := c.GetHeader("Authorization")
	if authHeader != "" {
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) == 2 && parts[0] == "Bearer" {
			accessToken = parts[1]
		}
	}

	if err := h.authService.LogoutAll(c.Request.Context(), userID, accessToken); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Logged out from all devices successfully"})
}

// SessionResponse represents a session in the response.
type SessionResponse struct {
	ID        string `json:"id"`                   // Short session identifier
	CreatedAt string `json:"created_at"`           // Session creation time
	ExpiresAt string `json:"expires_at"`           // Session expiration time
	IsCurrent bool   `json:"is_current,omitempty"` // Whether this is the current session
}

// SessionsResponse represents the response for listing sessions.
type SessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"` // List of sessions
	Total    int               `json:"total"`    // Total number of sessions
}

// GetSessions handles GET /api/v1/sessions endpoint.
// @Summary List active sessions
// @Description Get all active sessions for the authenticated user
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.APIResponse{data=SessionsResponse}
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/sessions [get]
func (h *AuthHandler) GetSessions(c *gin.Context) {
	userID := c.GetInt64("user_id")

	// Get current refresh token from context (if available)
	currentTokenID := c.GetString("refresh_token_id")

	sessions, err := h.authService.GetUserSessions(c.Request.Context(), userID, currentTokenID)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Convert to response format
	sessionResponses := make([]SessionResponse, 0, len(sessions))
	for _, s := range sessions {
		sessionResponses = append(sessionResponses, SessionResponse{
			ID:        s.ID,
			CreatedAt: s.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			ExpiresAt: s.ExpiresAt.Format("2006-01-02T15:04:05Z07:00"),
			IsCurrent: s.IsCurrent,
		})
	}

	response.Success(c, SessionsResponse{
		Sessions: sessionResponses,
		Total:    len(sessionResponses),
	})
}

// RevokeSessionRequest represents the request to revoke a session.
type RevokeSessionRequest struct {
	TokenID string `uri:"id" binding:"required"` // Session token ID (or short ID)
}

// RevokeSession handles DELETE /api/v1/sessions/:id endpoint.
// @Summary Revoke a session
// @Description Revoke a specific session by its ID
// @Tags auth
// @Security BearerAuth
// @Param id path string true "Session ID"
// @Produce json
// @Success 200 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	userID := c.GetInt64("user_id")
	sessionID := c.Param("id")

	if sessionID == "" {
		response.ValidationError(c, "session ID is required", nil)
		return
	}

	// Get user sessions to find the full token ID
	sessions, err := h.authService.GetUserSessions(c.Request.Context(), userID, "")
	if err != nil {
		response.Error(c, err)
		return
	}

	// Find the session by short ID or full ID
	var tokenIDToRevoke string
	for _, s := range sessions {
		if s.ID == sessionID || s.TokenID == sessionID {
			tokenIDToRevoke = s.TokenID
			break
		}
	}

	if tokenIDToRevoke == "" {
		response.NotFound(c, "session", sessionID)
		return
	}

	if err := h.authService.RevokeSession(c.Request.Context(), userID, tokenIDToRevoke); err != nil {
		response.Error(c, err)
		return
	}

	response.Success(c, gin.H{"message": "Session revoked successfully"})
}

// AuthMiddleware returns JWT authentication middleware.
//
// Validates the Authorization header, checks token blacklist, and extracts user claims.
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Unauthorized(c, "missing authorization header")
			c.Abort()
			return
		}

		// Parse "Bearer <token>" format
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			response.Unauthorized(c, "invalid authorization header format")
			c.Abort()
			return
		}

		claims, err := h.authService.ValidateToken(c.Request.Context(), parts[1])
		if err != nil {
			response.Unauthorized(c, "invalid or expired token")
			c.Abort()
			return
		}

		// Check if token is blacklisted
		if claims.ID != "" {
			isBlacklisted, blacklistErr := h.authService.IsTokenBlacklisted(c.Request.Context(), claims.ID)
			if blacklistErr != nil {
				h.logger.Warn("failed to check token blacklist", "error", blacklistErr)
				// Continue if blacklist check fails (fail-open for availability)
			} else if isBlacklisted {
				response.Unauthorized(c, "token has been revoked")
				c.Abort()
				return
			}
		}

		// Set user info in context
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)

		// Add user ID to logger context
		ctx := logger.WithUserIDContext(c.Request.Context(), claims.UserID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RBACMiddleware returns authorization middleware for a specific resource and action.
//
// Checks if the authenticated user has permission to perform the action on the resource.
func (h *AuthHandler) RBACMiddleware(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			response.Unauthorized(c, "")
			c.Abort()
			return
		}

		uid, ok := userID.(int64)
		if !ok {
			response.InternalError(c, "invalid user id type")
			c.Abort()
			return
		}
		allowed, err := h.authzService.CheckAccess(c.Request.Context(), uid, resource, action)
		if err != nil {
			h.logger.Error("authorization check failed", "user_id", userID, "resource", resource, "action", action, "error", err)
			response.InternalError(c, "authorization check failed")
			c.Abort()
			return
		}

		if !allowed {
			response.Forbidden(c, "insufficient permissions")
			c.Abort()
			return
		}

		c.Next()
	}
}
