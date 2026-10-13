package handler

import (
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
)

func sessionsRouter(f *authFixture) *gin.Engine {
	r := gin.New()
	api := r.Group("/api/v1", authenticated)
	api.GET("/sessions", f.h.ListSessions)
	api.DELETE("/sessions/:id", f.h.RevokeSession)
	return r
}

func TestListSessions_ReturnsTheCallerSessions(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	zone := time.FixedZone("UTC+3", 3*60*60)
	sessions := []domain.Session{
		{
			ID: testSessionID, TokenHash: "secret-token-hash", UserID: testUserID,
			CreatedAt: time.Date(2024, 1, 2, 6, 4, 5, 0, zone), ExpiresAt: time.Date(2024, 1, 9, 6, 4, 5, 0, zone),
			IP: testIP, UserAgent: "ua-current", Current: true,
		},
		{
			ID: "fedcba9876543210", TokenHash: "other-token-hash", UserID: testUserID,
			CreatedAt: time.Date(2024, 1, 3, 0, 0, 0, 0, time.UTC), ExpiresAt: time.Date(2024, 1, 10, 0, 0, 0, 0, time.UTC),
			IP: "198.51.100.7", UserAgent: "ua-other",
		},
	}
	f.auth.EXPECT().ListSessions(gomock.Any(), testUserID, testSessionID).Return(sessions, nil)

	rec := serve(sessionsRouter(f), newRequest(t, http.MethodGet, "/api/v1/sessions", nil))

	data := decodeSuccess[SessionsResponse](t, rec, http.StatusOK)
	assert.Equal(t, 2, data.Total)
	require.Len(t, data.Sessions, 2)
	assert.Equal(t, SessionResponse{
		ID: testSessionID, CreatedAt: time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC), ExpiresAt: time.Date(2024, 1, 9, 3, 4, 5, 0, time.UTC),
		IP: testIP, UserAgent: "ua-current", Current: true,
	}, data.Sessions[0])
	assert.Equal(t, "fedcba9876543210", data.Sessions[1].ID)
	assert.False(t, data.Sessions[1].Current)
	assert.Contains(t, rec.Body.String(), `"created_at":"2024-01-02T03:04:05Z"`, "timestamps are rendered in UTC")
	assert.NotContains(t, rec.Body.String(), "token-hash", "token hashes never leave the service")
}

func TestListSessions_EmptyListIsAnArray(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().ListSessions(gomock.Any(), testUserID, testSessionID).Return(nil, nil)

	rec := serve(sessionsRouter(f), newRequest(t, http.MethodGet, "/api/v1/sessions", nil))

	data := decodeSuccess[SessionsResponse](t, rec, http.StatusOK)
	assert.Zero(t, data.Total)
	assert.Empty(t, data.Sessions)
	assert.Contains(t, rec.Body.String(), `"sessions":[]`)
}

func TestListSessions_MapsServiceErrors(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	f.auth.EXPECT().ListSessions(gomock.Any(), testUserID, testSessionID).
		Return(nil, apperror.Internal("session store unavailable", errors.New("dial tcp: refused")))

	rec := serve(sessionsRouter(f), newRequest(t, http.MethodGet, "/api/v1/sessions", nil))

	assertError(t, rec, http.StatusInternalServerError, apperror.CodeInternal, "session store unavailable")
	assert.NotContains(t, rec.Body.String(), "dial tcp")
}

func TestRevokeSession(t *testing.T) {
	t.Parallel()

	t.Run("revokes the session by id", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().RevokeSession(gomock.Any(), testUserID, "fedcba9876543210", testMeta).Return(nil)

		rec := serve(sessionsRouter(f), newRequest(t, http.MethodDelete, "/api/v1/sessions/fedcba9876543210", nil))

		data := decodeSuccess[MessageResponse](t, rec, http.StatusOK)
		assert.Equal(t, "session revoked", data.Message)
	})

	t.Run("reports an unknown session", func(t *testing.T) {
		t.Parallel()
		f := newAuthFixture(t)
		f.auth.EXPECT().RevokeSession(gomock.Any(), testUserID, "missing", testMeta).Return(apperror.NotFound("session", "missing"))

		rec := serve(sessionsRouter(f), newRequest(t, http.MethodDelete, "/api/v1/sessions/missing", nil))

		errBody := assertError(t, rec, http.StatusNotFound, apperror.CodeNotFound, "session not found")
		assert.Equal(t, "missing", errBody.Details["id"])
	})
}
