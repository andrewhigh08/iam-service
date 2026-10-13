package handler

import (
	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// AuthMiddleware validates the bearer access token and stores the caller's user id and session
// id in the gin context. It answers 503 when token validation is unavailable.
func (h *AuthHandler) AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			abortUnauthorized(c, "missing authorization header")
			return
		}
		token, ok := bearerToken(c)
		if !ok {
			abortUnauthorized(c, "invalid authorization header format")
			return
		}

		claims, err := h.auth.ValidateAccessToken(c.Request.Context(), token)
		if err != nil {
			if isServiceUnavailable(err) {
				h.log.FromContext(c.Request.Context()).Error("access token validation unavailable", "error", err)
				response.Error(c, err)
				c.Abort()
				return
			}
			abortUnauthorized(c, "invalid or expired token")
			return
		}

		c.Set(ContextKeyUserID, claims.UserID)
		c.Set(ContextKeySessionID, claims.SessionID)
		c.Request = c.Request.WithContext(logger.WithUserIDContext(c.Request.Context(), claims.UserID))
		c.Next()
	}
}

// RBACMiddleware allows the request only when the authenticated user may perform action on
// resource. It must run after AuthMiddleware.
func (h *AuthHandler) RBACMiddleware(resource, action string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetInt64(ContextKeyUserID)
		if userID == 0 {
			abortUnauthorized(c, "")
			return
		}

		allowed, err := h.authz.CheckAccess(c.Request.Context(), userID, resource, action)
		if err != nil {
			h.log.FromContext(c.Request.Context()).Error("authorization check failed",
				"resource", resource, "action", action, "error", err)
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

func abortUnauthorized(c *gin.Context, message string) {
	response.Unauthorized(c, message)
	c.Abort()
}

func isServiceUnavailable(err error) bool {
	appErr, ok := apperror.AsAppError(err)
	return ok && appErr.Code == apperror.CodeServiceUnavailable
}
