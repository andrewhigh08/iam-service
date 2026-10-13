package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// AuthHandler serves the authentication endpoints and provides the auth and RBAC middleware.
type AuthHandler struct {
	auth  port.AuthService
	authz port.AuthorizationService
	log   *logger.Logger
}

// NewAuthHandler creates an AuthHandler.
func NewAuthHandler(auth port.AuthService, authz port.AuthorizationService, log *logger.Logger) *AuthHandler {
	return &AuthHandler{auth: auth, authz: authz, log: log.WithComponent("auth_handler")}
}

// LoginRequest is the body of POST /auth/login.
type LoginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

// UserInfo identifies the logged-in user.
type UserInfo struct {
	ID    int64    `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// LoginResponse is the body of a successful login. Either the token fields and User are set,
// or RequirePasswordChange is true and Reason tells why the password must be changed first.
type LoginResponse struct {
	AccessToken           string    `json:"access_token,omitempty"`
	RefreshToken          string    `json:"refresh_token,omitempty"`
	TokenType             string    `json:"token_type,omitempty"`
	ExpiresIn             int64     `json:"expires_in,omitempty"`
	User                  *UserInfo `json:"user,omitempty"`
	RequirePasswordChange bool      `json:"require_password_change,omitempty"`
	Reason                string    `json:"reason,omitempty"`
}

// TokenPairResponse carries a freshly issued token pair; ExpiresIn is the access token TTL in seconds.
type TokenPairResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// RefreshRequest is the body of POST /auth/refresh.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

// LogoutRequest is the body of POST /auth/logout. AccessToken is optional: when it is empty
// the Authorization header is used instead.
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
	AccessToken  string `json:"access_token"`
}

// MessageResponse is the body of endpoints that only confirm an action.
type MessageResponse struct {
	Message string `json:"message"`
}

// Login handles POST /auth/login.
// @Summary Log in
// @Description Checks the credentials and issues a token pair. When the password is temporary or expired the response carries require_password_change=true and a reason instead of tokens.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginRequest true "Credentials"
// @Success 200 {object} response.APIResponse{data=LoginResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 429 {object} response.APIResponse
// @Router /auth/login [post]
func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if !bindJSON(c, &req) {
		return
	}

	result, err := h.auth.Login(c.Request.Context(), req.Email, req.Password, clientMeta(c))
	if err != nil {
		response.Error(c, err)
		return
	}
	if result.RequirePasswordChange {
		response.Success(c, LoginResponse{RequirePasswordChange: true, Reason: result.Reason})
		return
	}
	if result.Tokens == nil || result.User == nil {
		h.log.FromContext(c.Request.Context()).Error("service returned no tokens or no user")
		response.InternalError(c, "failed to issue tokens")
		return
	}
	roles := result.Roles
	if roles == nil {
		roles = []string{}
	}
	response.Success(c, LoginResponse{
		AccessToken:  result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken,
		TokenType:    bearerScheme,
		ExpiresIn:    result.Tokens.ExpiresIn,
		User:         &UserInfo{ID: result.User.ID, Email: result.User.Email, Roles: roles},
	})
}

// Refresh handles POST /auth/refresh.
// @Summary Refresh tokens
// @Description Rotates the refresh token and issues a new token pair. The previous refresh token stops working.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body RefreshRequest true "Refresh token"
// @Success 200 {object} response.APIResponse{data=TokenPairResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /auth/refresh [post]
func (h *AuthHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if !bindJSON(c, &req) {
		return
	}

	pair, err := h.auth.Refresh(c.Request.Context(), req.RefreshToken, clientMeta(c))
	h.respondTokenPair(c, pair, err)
}

// Logout handles POST /auth/logout.
// @Summary Log out
// @Description Ends the session of the refresh token and revokes the access token given in the body or in the Authorization header.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LogoutRequest true "Tokens to invalidate"
// @Success 200 {object} response.APIResponse{data=MessageResponse}
// @Failure 400 {object} response.APIResponse
// @Router /auth/logout [post]
func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if !bindJSON(c, &req) {
		return
	}

	accessToken := req.AccessToken
	if accessToken == "" {
		accessToken, _ = bearerToken(c)
	}
	if err := h.auth.Logout(c.Request.Context(), req.RefreshToken, accessToken, clientMeta(c)); err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, MessageResponse{Message: "logged out"})
}

// LogoutAll handles POST /api/v1/logout-all.
// @Summary Log out everywhere
// @Description Ends every session of the caller and revokes all access tokens issued so far.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.APIResponse{data=MessageResponse}
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/logout-all [post]
func (h *AuthHandler) LogoutAll(c *gin.Context) {
	if err := h.auth.LogoutAll(c.Request.Context(), c.GetInt64(ContextKeyUserID), clientMeta(c)); err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, MessageResponse{Message: "logged out from all sessions"})
}

// respondTokenPair writes pair as a 200 response, or err when the service call failed.
func (h *AuthHandler) respondTokenPair(c *gin.Context, pair *port.TokenPair, err error) {
	if err != nil {
		response.Error(c, err)
		return
	}
	if pair == nil {
		h.log.FromContext(c.Request.Context()).Error("service returned no token pair")
		response.InternalError(c, "failed to issue tokens")
		return
	}
	response.Success(c, TokenPairResponse{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		TokenType:    bearerScheme,
		ExpiresIn:    pair.ExpiresIn,
	})
}
