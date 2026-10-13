package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLive_ReportsTheVersion(t *testing.T) {
	t.Parallel()
	r := gin.New()
	r.GET("/health/live", NewHealthHandler(nil, nil, "1.2.3").Live)

	rec := serve(r, newRequest(t, http.MethodGet, "/health/live", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{"status":"ok","version":"1.2.3"}`, rec.Body.String())
}

func TestReady_IsDegradedWithoutItsDependencies(t *testing.T) {
	t.Parallel()
	var attached []string
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Next()
		attached = c.Errors.Errors()
	})
	r.GET("/health/ready", NewHealthHandler(nil, nil, "1.2.3").Ready)

	rec := serve(r, newRequest(t, http.MethodGet, "/health/ready", nil))

	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	var body ReadyResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	assert.Equal(t, "degraded", body.Status)
	assert.Equal(t, map[string]Check{
		"database": {Status: "unhealthy", Message: "database is unavailable"},
		"redis":    {Status: "unhealthy", Message: "redis is unavailable"},
	}, body.Checks)
	assert.NotContains(t, rec.Body.String(), "not configured", "the cause stays out of the response")
	assert.ElementsMatch(t, []string{"database check: not configured", "redis check: not configured"}, attached,
		"the causes are attached to the context for the access log")
}
