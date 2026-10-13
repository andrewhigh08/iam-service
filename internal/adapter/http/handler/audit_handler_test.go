package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

func auditRouter(t *testing.T) (*gin.Engine, *mocks.MockAuditService) {
	t.Helper()
	audit := mocks.NewMockAuditService(gomock.NewController(t))
	r := gin.New()
	r.GET("/api/v1/users/:id/audit", authenticated, NewAuditHandler(audit).ListUserAudit)
	return r, audit
}

func TestListUserAudit_ReturnsEntriesNewestFirst(t *testing.T) {
	t.Parallel()
	r, audit := auditRouter(t)
	ip, ua := "203.0.113.9", "admin-ui/2.0"
	zone := time.FixedZone("UTC+3", 3*60*60)
	entries := []domain.AuditLog{
		{
			ID: 12, ActorID: 7, Action: domain.AuditActionUserBlock, ResourceType: domain.AuditResourceTypeUser, ResourceID: "9",
			Details: json.RawMessage(`{"email":"bob@example.com"}`), IPAddress: &ip, UserAgent: &ua,
			CreatedAt: time.Date(2024, 1, 2, 6, 4, 5, 0, zone),
		},
		{ID: 11, ActorID: 7, Action: domain.AuditActionLogout, ResourceType: domain.AuditResourceTypeUser, ResourceID: "7", CreatedAt: time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	audit.EXPECT().ListByActor(gomock.Any(), int64(7), 2).Return(entries, nil)

	rec := serve(r, newRequest(t, http.MethodGet, "/api/v1/users/7/audit?limit=2", nil))

	data := decodeSuccess[AuditEntriesResponse](t, rec, http.StatusOK)
	assert.Equal(t, 2, data.Total)
	require.Len(t, data.Entries, 2)
	assert.Equal(t, AuditEntryResponse{
		ID: 12, ActorID: 7, Action: domain.AuditActionUserBlock, ResourceType: domain.AuditResourceTypeUser, ResourceID: "9",
		Details: map[string]any{"email": "bob@example.com"}, IP: ip, UserAgent: ua,
		CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC),
	}, data.Entries[0])
	assert.Equal(t, int64(11), data.Entries[1].ID)
	assert.Nil(t, data.Entries[1].Details)
	assert.Contains(t, rec.Body.String(), `"created_at":"2024-01-02T03:04:05Z"`, "timestamps are rendered in UTC")
}

func TestListUserAudit_BoundsTheLimit(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		query string
		want  int
	}{
		{"default", "", defaultAuditLimit},
		{"explicit", "?limit=5", 5},
		{"above the maximum", "?limit=1000", maxAuditLimit},
		{"zero", "?limit=0", 1},
		{"not a number", "?limit=many", defaultAuditLimit},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r, audit := auditRouter(t)
			audit.EXPECT().ListByActor(gomock.Any(), int64(7), tt.want).Return(nil, nil)

			rec := serve(r, newRequest(t, http.MethodGet, "/api/v1/users/7/audit"+tt.query, nil))

			data := decodeSuccess[AuditEntriesResponse](t, rec, http.StatusOK)
			assert.Zero(t, data.Total)
			assert.Contains(t, rec.Body.String(), `"entries":[]`)
		})
	}
}

func TestListUserAudit_Errors(t *testing.T) {
	t.Parallel()
	t.Run("invalid user id", func(t *testing.T) {
		t.Parallel()
		r, _ := auditRouter(t)

		rec := serve(r, newRequest(t, http.MethodGet, "/api/v1/users/abc/audit", nil))

		assertError(t, rec, http.StatusBadRequest, apperror.CodeBadRequest, "invalid user id")
	})
	t.Run("service failure", func(t *testing.T) {
		t.Parallel()
		r, audit := auditRouter(t)
		audit.EXPECT().ListByActor(gomock.Any(), int64(7), defaultAuditLimit).
			Return(nil, apperror.Internal("failed to list audit entries", errors.New("dial tcp: refused")))

		rec := serve(r, newRequest(t, http.MethodGet, "/api/v1/users/7/audit", nil))

		assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "failed to list audit entries")
		assert.NotContains(t, rec.Body.String(), "dial tcp")
	})
}
