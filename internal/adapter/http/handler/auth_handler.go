// Package handler provides HTTP request handlers for the IAM service.
// Пакет handler предоставляет обработчики HTTP запросов для IAM сервиса.
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
// AuthHandler обрабатывает HTTP запросы, связанные с аутентификацией.
//
// Provides endpoints for login, password change, and token validation.
// Предоставляет эндпоинты для входа, смены пароля и валидации токенов.
type AuthHandler struct {
	authService  port.AuthService          // Authentication service / Сервис аутентификации
	authzService port.AuthorizationService // Authorization service / Сервис авторизации
	logger       *logger.Logger            // Logger instance / Экземпляр логгера
}

// NewAuthHandler creates a new AuthHandler instance.
// NewAuthHandler создаёт новый экземпляр AuthHandler.
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
// LoginRequest представляет тело запроса на вход.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"` // User email / Email пользователя
	Password string `json:"password" binding:"required"`    // User password / Пароль пользователя
}

// LoginResponse represents a successful login response.
// LoginResponse представляет успешный ответ на вход.
type LoginResponse struct {
	AccessToken  string    `json:"access_token,omitempty"`  // JWT access token / JWT токен доступа
	RefreshToken string    `json:"refresh_token,omitempty"` // Refresh token for obtaining new access tokens / Refresh токен для получения новых access токенов
	TokenType    string    `json:"token_type,omitempty"`    // Token type (Bearer) / Тип токена (Bearer)
	User         *UserInfo `json:"user,omitempty"`          // User information / Информация о пользователе
	// For OTP flow / Для потока OTP
	RequirePasswordChange bool   `json:"require_password_change,omitempty"` // OTP password change required / Требуется смена OTP пароля
	UserID                int64  `json:"user_id,omitempty"`                 // User ID for OTP flow / ID пользователя для OTP
	Message               string `json:"message,omitempty"`                 // Additional message / Дополнительное сообщение
}

// UserInfo represents user information in responses.
// UserInfo представляет информацию о пользователе в ответах.
type UserInfo struct {
	ID    int64    `json:"id"`    // User ID / ID пользователя
	Email string   `json:"email"` // User email / Email пользователя
	Roles []string `json:"roles"` // User roles / Роли пользователя
}

// Login handles POST /auth/login endpoint.
// Login обрабатывает POST /auth/login эндпоинт.
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

	// Handle one-time password flow / Обрабатываем поток одноразового пароля
	if isOTP {
		// Get user to return user ID / Получаем пользователя для возврата ID
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

	// Get user info for response / Получаем информацию о пользователе для ответа
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
// ChangePasswordRequest представляет тело запроса на смену пароля.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`       // Current password / Текущий пароль
	NewPassword string `json:"new_password" binding:"required,min=8"` // New password (min 8 chars) / Новый пароль (мин. 8 символов)
}

// ChangePassword handles POST /api/v1/change-password.
// ChangePassword обрабатывает POST /api/v1/change-password.
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

	// Validate password complexity / Проверяем сложность пароля
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
// FirstTimePasswordChangeRequest представляет запрос на первую смену пароля.
type FirstTimePasswordChangeRequest struct {
	UserID      int64  `json:"user_id" binding:"required"`            // User ID / ID пользователя
	OldPassword string `json:"old_password" binding:"required"`       // OTP password / OTP пароль
	NewPassword string `json:"new_password" binding:"required,min=8"` // New permanent password / Новый постоянный пароль
}

// FirstTimePasswordChangeResponse represents the response after first-time password change.
// FirstTimePasswordChangeResponse представляет ответ после первой смены пароля.
type FirstTimePasswordChangeResponse struct {
	Message      string   `json:"message"`       // Success message / Сообщение об успехе
	AccessToken  string   `json:"access_token"`  // JWT access token / JWT access токен
	RefreshToken string   `json:"refresh_token"` // Refresh token / Refresh токен
	TokenType    string   `json:"token_type"`    // Token type / Тип токена
	Roles        []string `json:"roles"`         // User roles / Роли пользователя
}

// FirstTimePasswordChange handles POST /auth/first-time-password-change.
// FirstTimePasswordChange обрабатывает POST /auth/first-time-password-change.
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

	// Validate password complexity / Проверяем сложность пароля
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

	// Generate token pair for the user / Генерируем пару токенов для пользователя
	tokens, err := h.authService.GenerateTokenForUser(c.Request.Context(), req.UserID)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Get user roles / Получаем роли пользователя
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
// RefreshTokenRequest представляет тело запроса на обновление токена.
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // Refresh token / Refresh токен
}

// RefreshTokenResponse represents the refresh token response.
// RefreshTokenResponse представляет ответ на обновление токена.
type RefreshTokenResponse struct {
	AccessToken string `json:"access_token"` // New access token / Новый access токен
	TokenType   string `json:"token_type"`   // Token type (Bearer) / Тип токена (Bearer)
}

// RefreshToken handles POST /auth/refresh endpoint.
// RefreshToken обрабатывает POST /auth/refresh эндпоинт.
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
// LogoutRequest представляет тело запроса на выход.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"` // Refresh token to invalidate / Refresh токен для инвалидации
	AccessToken  string `json:"access_token,omitempty"`           // Access token to blacklist (optional) / Access токен для blacklist (опционально)
}

// Logout handles POST /auth/logout endpoint.
// Logout обрабатывает POST /auth/logout эндпоинт.
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
// LogoutAll обрабатывает POST /api/v1/logout-all эндпоинт.
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
	// Извлекаем текущий access токен из заголовка Authorization
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
// SessionResponse представляет сессию в ответе.
type SessionResponse struct {
	ID        string `json:"id"`                   // Short session identifier / Короткий идентификатор сессии
	CreatedAt string `json:"created_at"`           // Session creation time / Время создания сессии
	ExpiresAt string `json:"expires_at"`           // Session expiration time / Время истечения сессии
	IsCurrent bool   `json:"is_current,omitempty"` // Whether this is the current session / Является ли это текущей сессией
}

// SessionsResponse represents the response for listing sessions.
// SessionsResponse представляет ответ для списка сессий.
type SessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"` // List of sessions / Список сессий
	Total    int               `json:"total"`    // Total number of sessions / Общее количество сессий
}

// GetSessions handles GET /api/v1/sessions endpoint.
// GetSessions обрабатывает GET /api/v1/sessions эндпоинт.
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
	// Получаем текущий refresh токен из контекста (если доступен)
	currentTokenID := c.GetString("refresh_token_id")

	sessions, err := h.authService.GetUserSessions(c.Request.Context(), userID, currentTokenID)
	if err != nil {
		response.Error(c, err)
		return
	}

	// Convert to response format / Конвертируем в формат ответа
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
// RevokeSessionRequest представляет запрос на отзыв сессии.
type RevokeSessionRequest struct {
	TokenID string `uri:"id" binding:"required"` // Session token ID (or short ID) / ID токена сессии (или короткий ID)
}

// RevokeSession handles DELETE /api/v1/sessions/:id endpoint.
// RevokeSession обрабатывает DELETE /api/v1/sessions/:id эндпоинт.
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
	// Получаем сессии пользователя для поиска полного ID токена
	sessions, err := h.authService.GetUserSessions(c.Request.Context(), userID, "")
	if err != nil {
		response.Error(c, err)
		return
	}

	// Find the session by short ID or full ID
	// Находим сессию по короткому ID или полному ID
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
// AuthMiddleware возвращает middleware для JWT аутентификации.
//
// Validates the Authorization header, checks token blacklist, and extracts user claims.
// Валидирует заголовок Authorization, проверяет blacklist токенов и извлекает claims пользователя.
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			response.Unauthorized(c, "missing authorization header")
			c.Abort()
			return
		}

		// Parse "Bearer <token>" format / Парсим формат "Bearer <token>"
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

		// Check if token is blacklisted / Проверяем, находится ли токен в blacklist
		if claims.ID != "" {
			isBlacklisted, blacklistErr := h.authService.IsTokenBlacklisted(c.Request.Context(), claims.ID)
			if blacklistErr != nil {
				h.logger.Warn("failed to check token blacklist", "error", blacklistErr)
				// Continue if blacklist check fails (fail-open for availability)
				// Продолжаем, если проверка blacklist не удалась (fail-open для доступности)
			} else if isBlacklisted {
				response.Unauthorized(c, "token has been revoked")
				c.Abort()
				return
			}
		}

		// Set user info in context / Устанавливаем информацию о пользователе в контекст
		c.Set("user_id", claims.UserID)
		c.Set("email", claims.Email)
		c.Set("roles", claims.Roles)

		// Add user ID to logger context / Добавляем ID пользователя в контекст логгера
		ctx := logger.WithUserIDContext(c.Request.Context(), claims.UserID)
		c.Request = c.Request.WithContext(ctx)

		c.Next()
	}
}

// RBACMiddleware returns authorization middleware for a specific resource and action.
// RBACMiddleware возвращает middleware авторизации для конкретного ресурса и действия.
//
// Checks if the authenticated user has permission to perform the action on the resource.
// Проверяет, имеет ли аутентифицированный пользователь разрешение на выполнение действия над ресурсом.
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
