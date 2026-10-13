package handler

import (
	"time"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
)

// SessionResponse describes one live session of the caller.
type SessionResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

// SessionsResponse is the body of GET /api/v1/sessions.
type SessionsResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int               `json:"total"`
}

// ListSessions handles GET /api/v1/sessions.
// @Summary List sessions
// @Description Lists the live sessions of the caller; the one serving this request is marked current.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Success 200 {object} response.APIResponse{data=SessionsResponse}
// @Failure 401 {object} response.APIResponse
// @Router /api/v1/sessions [get]
func (h *AuthHandler) ListSessions(c *gin.Context) {
	sessions, err := h.auth.ListSessions(c.Request.Context(), c.GetInt64(ContextKeyUserID), c.GetString(ContextKeySessionID))
	if err != nil {
		response.Error(c, err)
		return
	}

	items := make([]SessionResponse, len(sessions))
	for i := range sessions {
		items[i] = newSessionResponse(&sessions[i])
	}
	response.Success(c, SessionsResponse{Sessions: items, Total: len(items)})
}

// RevokeSession handles DELETE /api/v1/sessions/:id.
// @Summary Revoke a session
// @Description Ends one session of the caller by its id and revokes the access token issued with it.
// @Tags auth
// @Security BearerAuth
// @Produce json
// @Param id path string true "Session id"
// @Success 200 {object} response.APIResponse{data=MessageResponse}
// @Failure 401 {object} response.APIResponse
// @Failure 404 {object} response.APIResponse
// @Router /api/v1/sessions/{id} [delete]
func (h *AuthHandler) RevokeSession(c *gin.Context) {
	if err := h.auth.RevokeSession(c.Request.Context(), c.GetInt64(ContextKeyUserID), c.Param("id"), clientMeta(c)); err != nil {
		response.Error(c, err)
		return
	}
	response.Success(c, MessageResponse{Message: "session revoked"})
}

func newSessionResponse(s *domain.Session) SessionResponse {
	return SessionResponse{
		ID:        s.ID,
		CreatedAt: s.CreatedAt.UTC(),
		ExpiresAt: s.ExpiresAt.UTC(),
		IP:        s.IP,
		UserAgent: s.UserAgent,
		Current:   s.Current,
	}
}
