package handler

import (
	"encoding/json"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	defaultAuditLimit = 50
	maxAuditLimit     = 100
)

// AuditHandler serves the audit log endpoints.
type AuditHandler struct {
	audit port.AuditService
}

// NewAuditHandler creates an AuditHandler.
func NewAuditHandler(audit port.AuditService) *AuditHandler {
	return &AuditHandler{audit: audit}
}

// AuditEntryResponse describes one audit entry.
type AuditEntryResponse struct {
	ID           int64          `json:"id"`
	ActorID      int64          `json:"actor_id"`
	Action       string         `json:"action"`
	ResourceType string         `json:"resource_type"`
	ResourceID   string         `json:"resource_id"`
	Details      map[string]any `json:"details,omitempty"`
	IP           string         `json:"ip,omitempty"`
	UserAgent    string         `json:"user_agent,omitempty"`
	CreatedAt    time.Time      `json:"created_at"`
}

// AuditEntriesResponse is the body of GET /api/v1/users/:id/audit.
type AuditEntriesResponse struct {
	Entries []AuditEntryResponse `json:"entries"`
	Total   int                  `json:"total"`
}

// ListUserAudit handles GET /api/v1/users/:id/audit.
// @Summary List a user's audit trail
// @Description Lists the most recent audit entries recorded for actions of the user, newest first. An id without entries yields an empty list.
// @Tags audit
// @Security BearerAuth
// @Produce json
// @Param id path int true "User id"
// @Param limit query int false "Entries to return, 1 to 100" default(50)
// @Success 200 {object} response.APIResponse{data=AuditEntriesResponse}
// @Failure 400 {object} response.APIResponse
// @Failure 401 {object} response.APIResponse
// @Failure 403 {object} response.APIResponse
// @Router /api/v1/users/{id}/audit [get]
func (h *AuditHandler) ListUserAudit(c *gin.Context) {
	id, ok := userIDParam(c)
	if !ok {
		return
	}
	limit := min(max(1, queryInt(c, "limit", defaultAuditLimit)), maxAuditLimit)

	entries, err := h.audit.ListByActor(c.Request.Context(), id, limit)
	if err != nil {
		response.Error(c, err)
		return
	}
	items := make([]AuditEntryResponse, len(entries))
	for i := range entries {
		items[i] = newAuditEntryResponse(&entries[i])
	}
	response.Success(c, AuditEntriesResponse{Entries: items, Total: len(items)})
}

// newAuditEntryResponse maps an audit entry to its DTO with the timestamp in UTC. Details that
// are not a JSON object are left out.
func newAuditEntryResponse(e *domain.AuditLog) AuditEntryResponse {
	out := AuditEntryResponse{
		ID:           e.ID,
		ActorID:      e.ActorID,
		Action:       e.Action,
		ResourceType: e.ResourceType,
		ResourceID:   e.ResourceID,
		CreatedAt:    e.CreatedAt.UTC(),
	}
	if e.IPAddress != nil {
		out.IP = *e.IPAddress
	}
	if e.UserAgent != nil {
		out.UserAgent = *e.UserAgent
	}
	if len(e.Details) > 0 {
		_ = json.Unmarshal(e.Details, &out.Details)
	}
	return out
}
