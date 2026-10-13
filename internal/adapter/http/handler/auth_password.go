package handler

import (
	"github.com/gin-gonic/gin"
)

// ChangePasswordRequest is the body of POST /api/v1/change-password.
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangeRequiredPasswordRequest is the body of POST /auth/change-password.
type ChangeRequiredPasswordRequest struct {
	Email       string `json:"email" binding:"required,max=254,email"`
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword handles POST /api/v1/change-password.
// @Summary Change password
// @Description Replaces the caller's password, ends every session including the caller's and returns a fresh token pair. The new password must satisfy the password policy.
// @Tags auth
// @Security BearerAuth
// @Accept json
// @Produce json
// @Param request body ChangePasswordRequest true "Current and new password"
// @Success 200 {object} response.APIResponse{data=TokenPairResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/change-password [post]
func (h *AuthHandler) ChangePassword(c *gin.Context) {
	var req ChangePasswordRequest
	if !bindJSON(c, &req) {
		return
	}

	pair, err := h.auth.ChangePassword(c.Request.Context(), c.GetInt64(ContextKeyUserID), req.OldPassword, req.NewPassword, clientMeta(c))
	h.respondTokenPair(c, pair, err)
}

// ChangeRequiredPassword handles POST /auth/change-password.
// @Summary Change a temporary or expired password
// @Description Completes a login that required a password change. Only allowed while the password is temporary or expired; rate limited like login.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body ChangeRequiredPasswordRequest true "Email, current and new password"
// @Success 200 {object} response.APIResponse{data=TokenPairResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 429 {object} response.APIResponse
// @Router /auth/change-password [post]
func (h *AuthHandler) ChangeRequiredPassword(c *gin.Context) {
	var req ChangeRequiredPasswordRequest
	if !bindJSON(c, &req) {
		return
	}

	pair, err := h.auth.ChangeRequiredPassword(c.Request.Context(), req.Email, req.OldPassword, req.NewPassword, clientMeta(c))
	h.respondTokenPair(c, pair, err)
}
