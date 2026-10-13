package middleware

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

func accessLogRouter(buf *bytes.Buffer, h gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(RequestID(), AccessLog(newLogger(buf)))
	r.GET("/users/:id", h)
	return r
}

func singleRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	records := logRecords(t, buf)
	require.Len(t, records, 1)
	return records[0]
}

func TestAccessLog_LogsTheCompletedRequest(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := accessLogRouter(&buf, func(c *gin.Context) {
		c.Request = c.Request.WithContext(logger.WithUserIDContext(c.Request.Context(), 42))
		okHandler(c)
	})
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/users/42", http.NoBody)
	req.Header.Set(RequestIDHeader, "req-1")
	req.RemoteAddr = "203.0.113.9:1234"

	rec := serve(r, req)

	require.Equal(t, http.StatusOK, rec.Code)
	log := singleRecord(t, &buf)
	assert.Equal(t, "INFO", log["level"])
	assert.Equal(t, "request completed", log["msg"])
	assert.Equal(t, http.MethodGet, log["method"])
	assert.Equal(t, "/users/:id", log["route"], "the route template is logged, not the raw path")
	assert.InDelta(t, http.StatusOK, log["status"], 0)
	assert.Equal(t, "203.0.113.9", log["client_ip"])
	assert.Equal(t, "req-1", log["request_id"])
	assert.InDelta(t, 42, log["user_id"], 0, "the user id set later in the chain is picked up")
	duration, ok := log["duration_ms"].(float64)
	require.True(t, ok, "duration_ms must be numeric")
	assert.GreaterOrEqual(t, duration, 0.0)
	assert.NotContains(t, log, "panic")
	assert.NotContains(t, log, "errors")
}

func TestAccessLog_LogsServerErrorsAtWarnWithTheirErrors(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := accessLogRouter(&buf, func(c *gin.Context) {
		_ = c.Error(errors.New("db exploded"))
		c.Status(http.StatusInternalServerError)
	})

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/users/1", http.NoBody))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	log := singleRecord(t, &buf)
	assert.Equal(t, "WARN", log["level"])
	assert.InDelta(t, http.StatusInternalServerError, log["status"], 0)
	assert.Equal(t, []any{"db exploded"}, log["errors"])
}

func TestAccessLog_ClientErrorsStayAtInfo(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := accessLogRouter(&buf, func(c *gin.Context) { c.Status(http.StatusNotFound) })

	serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/users/1", http.NoBody))

	log := singleRecord(t, &buf)
	assert.Equal(t, "INFO", log["level"])
	assert.InDelta(t, http.StatusNotFound, log["status"], 0)
}

func TestAccessLog_UnmatchedRouteLogsThePath(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := accessLogRouter(&buf, okHandler)

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/missing", http.NoBody))

	require.Equal(t, http.StatusNotFound, rec.Code)
	log := singleRecord(t, &buf)
	assert.Equal(t, "/missing", log["route"])
	assert.InDelta(t, http.StatusNotFound, log["status"], 0)
}

func TestAccessLog_LogsAPanicAs500AndPassesItOn(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	lg := newLogger(&buf)
	r := gin.New()
	r.Use(Recovery(lg), AccessLog(lg))
	r.GET("/boom", func(*gin.Context) { panic("boom") })

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/boom", http.NoBody))

	require.Equal(t, http.StatusInternalServerError, rec.Code, "Recovery still receives the panic")
	records := logRecords(t, &buf)
	require.Len(t, records, 2)
	access := records[0]
	assert.Equal(t, "request completed", access["msg"])
	assert.Equal(t, "WARN", access["level"])
	assert.InDelta(t, http.StatusInternalServerError, access["status"], 0)
	panicked, ok := access["panic"].(bool)
	require.True(t, ok, "panic must be a boolean attribute")
	assert.True(t, panicked)
	assert.Equal(t, "panic recovered", records[1]["msg"])
}
