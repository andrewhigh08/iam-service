package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	healthOK       = "ok"
	healthDegraded = "degraded"
	checkHealthy   = "healthy"
	checkUnhealthy = "unhealthy"
	readyTimeout   = 5 * time.Second
)

var errNotConfigured = errors.New("not configured")

// Pinger verifies that a dependency can be reached.
type Pinger interface {
	Ping(ctx context.Context) error
}

// PingerFunc adapts a function to the Pinger interface.
type PingerFunc func(ctx context.Context) error

// Ping calls f.
func (f PingerFunc) Ping(ctx context.Context) error {
	return f(ctx)
}

// HealthHandler serves the liveness and readiness probes.
type HealthHandler struct {
	checks  map[string]Pinger
	version string
}

// NewHealthHandler creates a HealthHandler. The readiness probe reports every entry of checks
// under its key, counting a nil Pinger as unreachable; version is reported by the liveness probe.
func NewHealthHandler(checks map[string]Pinger, version string) *HealthHandler {
	return &HealthHandler{checks: checks, version: version}
}

// LiveResponse is the body of GET /health/live.
type LiveResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// ReadyResponse is the body of GET /health/ready.
type ReadyResponse struct {
	Status string           `json:"status"`
	Checks map[string]Check `json:"checks"`
}

// Check is the outcome of one dependency check. Message is generic and never carries the cause.
type Check struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

// Live handles GET /health/live.
// @Summary Liveness probe
// @Description Reports that the process is running and which version it is.
// @Tags health
// @Produce json
// @Success 200 {object} LiveResponse
// @Router /health/live [get]
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, LiveResponse{Status: healthOK, Version: h.version})
}

// Ready handles GET /health/ready.
// @Summary Readiness probe
// @Description Pings the database and Redis; answers 503 with status "degraded" when either is unreachable.
// @Tags health
// @Produce json
// @Success 200 {object} ReadyResponse
// @Failure 503 {object} ReadyResponse
// @Router /health/ready [get]
func (h *HealthHandler) Ready(c *gin.Context) {
	ctx, cancel := context.WithTimeout(c.Request.Context(), readyTimeout)
	defer cancel()

	status, code := healthOK, http.StatusOK
	checks := make(map[string]Check, len(h.checks))
	for name, pinger := range h.checks {
		chk := check(c, name, ping(ctx, pinger))
		if chk.Status != checkHealthy {
			status, code = healthDegraded, http.StatusServiceUnavailable
		}
		checks[name] = chk
	}
	c.JSON(code, ReadyResponse{Status: status, Checks: checks})
}

// ping runs p within ctx; a nil p counts as unreachable.
func ping(ctx context.Context, p Pinger) error {
	if p == nil {
		return errNotConfigured
	}
	return p.Ping(ctx)
}

// check renders the outcome of pinging name. The cause is attached to the gin context for the
// access log and replaced by a generic message in the response.
func check(c *gin.Context, name string, err error) Check {
	if err == nil {
		return Check{Status: checkHealthy}
	}
	_ = c.Error(fmt.Errorf("%s check: %w", name, err))
	return Check{Status: checkUnhealthy, Message: name + " is unavailable"}
}
