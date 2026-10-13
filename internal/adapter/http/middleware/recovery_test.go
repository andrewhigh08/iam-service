package middleware

import (
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"syscall"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// recoveryRouter serves GET /panic behind RequestID and Recovery with the given handler.
func recoveryRouter(buf *bytes.Buffer, h gin.HandlerFunc) *gin.Engine {
	r := gin.New()
	r.Use(RequestID(), Recovery(newLogger(buf)))
	r.GET("/panic", h)
	return r
}

func TestRecovery_PanicBecomesEnvelope500(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
	}{
		{"string", "boom"},
		{"error", errors.New("kaboom")},
		{"integer", 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r := recoveryRouter(&buf, func(*gin.Context) { panic(tt.value) })
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/panic", http.NoBody)
			req.Header.Set(RequestIDHeader, "req-panic")

			rec := serve(r, req)

			require.Equal(t, http.StatusInternalServerError, rec.Code)
			env := decodeEnvelope(t, rec)
			assert.False(t, env.Success)
			require.NotNil(t, env.Error)
			assert.Equal(t, apperror.CodeInternal, env.Error.Code)
			assert.Equal(t, "internal server error", env.Error.Message)

			records := logRecords(t, &buf)
			require.Len(t, records, 1)
			log := records[0]
			assert.Equal(t, "ERROR", log["level"])
			assert.Equal(t, "panic recovered", log["msg"])
			assert.Equal(t, fmt.Sprint(tt.value), log["panic"])
			assert.Equal(t, http.MethodGet, log["method"])
			assert.Equal(t, "/panic", log["path"])
			assert.Equal(t, "req-panic", log["request_id"])
			assert.NotEmpty(t, log["stack"])
		})
	}
}

func TestRecovery_ConnectionLostIsOnlyLogged(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value error
	}{
		{"aborted handler", http.ErrAbortHandler},
		{"wrapped broken pipe", fmt.Errorf("write tcp: %w", syscall.EPIPE)},
		{"connection reset", syscall.ECONNRESET},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			r := recoveryRouter(&buf, func(*gin.Context) { panic(tt.value) })

			rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/panic", http.NoBody))

			assert.Empty(t, rec.Body.String(), "nothing can be sent to a client that went away")

			records := logRecords(t, &buf)
			require.Len(t, records, 1)
			log := records[0]
			assert.Equal(t, "WARN", log["level"])
			assert.Equal(t, "connection lost while handling request", log["msg"])
			assert.Equal(t, tt.value.Error(), log["reason"])
			assert.NotContains(t, log, "stack")
		})
	}
}

func TestRecovery_KeepsAPartiallyWrittenResponse(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := recoveryRouter(&buf, func(c *gin.Context) {
		c.String(http.StatusOK, "partial")
		panic("too late")
	})

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/panic", http.NoBody))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "partial", rec.Body.String())
	records := logRecords(t, &buf)
	require.Len(t, records, 1)
	assert.Equal(t, "panic recovered", records[0]["msg"])
}

func TestRecovery_PassesThroughWithoutPanic(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	r := recoveryRouter(&buf, okHandler)

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/panic", http.NoBody))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "ok", rec.Body.String())
	assert.Empty(t, buf.String())
}

func TestIsConnectionLost(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		value any
		want  bool
	}{
		{"nil", nil, false},
		{"string", "boom", false},
		{"ordinary error", errors.New("boom"), false},
		{"aborted handler", http.ErrAbortHandler, true},
		{"broken pipe", syscall.EPIPE, true},
		{"wrapped connection reset", fmt.Errorf("write: %w", syscall.ECONNRESET), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isConnectionLost(tt.value))
		})
	}
}
