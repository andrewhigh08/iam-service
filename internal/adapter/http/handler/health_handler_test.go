package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// healthFixture serves the probes of a HealthHandler and keeps the errors the last request
// attached to the gin context.
type healthFixture struct {
	r        *gin.Engine
	attached []string
}

func newHealthFixture(checks map[string]Pinger) *healthFixture {
	f := &healthFixture{r: gin.New()}
	f.r.Use(func(c *gin.Context) {
		c.Next()
		f.attached = c.Errors.Errors()
	})
	h := NewHealthHandler(checks, "1.2.3")
	f.r.GET("/health/live", h.Live)
	f.r.GET("/health/ready", h.Ready)
	return f
}

func pinger(err error) Pinger {
	return PingerFunc(func(context.Context) error { return err })
}

func TestLive_ReportsTheVersion(t *testing.T) {
	t.Parallel()
	f := newHealthFixture(nil)

	rec := serve(f.r, newRequest(t, http.MethodGet, "/health/live", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok","version":"1.2.3"}`, rec.Body.String())
}

func TestReady_ReportsEveryCheck(t *testing.T) {
	t.Parallel()
	errDial := errors.New("dial tcp 10.0.0.1:5432: connection refused")
	tests := []struct {
		name         string
		checks       map[string]Pinger
		wantCode     int
		wantStatus   string
		wantChecks   map[string]Check
		wantAttached []string
	}{
		{
			name:       "all reachable",
			checks:     map[string]Pinger{"database": pinger(nil), "redis": pinger(nil)},
			wantCode:   http.StatusOK,
			wantStatus: "ok",
			wantChecks: map[string]Check{"database": {Status: "healthy"}, "redis": {Status: "healthy"}},
		},
		{
			name:       "one unreachable",
			checks:     map[string]Pinger{"database": pinger(errDial), "redis": pinger(nil)},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: "degraded",
			wantChecks: map[string]Check{
				"database": {Status: "unhealthy", Message: "database is unavailable"},
				"redis":    {Status: "healthy"},
			},
			wantAttached: []string{"database check: dial tcp 10.0.0.1:5432: connection refused"},
		},
		{
			name:       "not configured",
			checks:     map[string]Pinger{"database": nil, "redis": nil},
			wantCode:   http.StatusServiceUnavailable,
			wantStatus: "degraded",
			wantChecks: map[string]Check{
				"database": {Status: "unhealthy", Message: "database is unavailable"},
				"redis":    {Status: "unhealthy", Message: "redis is unavailable"},
			},
			wantAttached: []string{"database check: not configured", "redis check: not configured"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			f := newHealthFixture(tt.checks)

			rec := serve(f.r, newRequest(t, http.MethodGet, "/health/ready", nil))

			require.Equal(t, tt.wantCode, rec.Code, "body: %s", rec.Body.String())
			var body ReadyResponse
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			assert.Equal(t, tt.wantStatus, body.Status)
			assert.Equal(t, tt.wantChecks, body.Checks)
			assert.NotContains(t, rec.Body.String(), "dial tcp", "the cause stays out of the response")
			assert.NotContains(t, rec.Body.String(), "not configured", "the cause stays out of the response")
			assert.ElementsMatch(t, tt.wantAttached, f.attached, "the causes are attached to the context for the access log")
		})
	}
}

func TestReady_BoundsEveryCheck(t *testing.T) {
	t.Parallel()
	var bounded bool
	f := newHealthFixture(map[string]Pinger{"database": PingerFunc(func(ctx context.Context) error {
		_, bounded = ctx.Deadline()
		return nil
	})})

	rec := serve(f.r, newRequest(t, http.MethodGet, "/health/ready", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, bounded, "a check runs under the readiness timeout")
}
