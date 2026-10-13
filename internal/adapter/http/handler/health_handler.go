package handler

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"
)

const (
	healthOK       = "ok"
	healthDegraded = "degraded"
	checkHealthy   = "healthy"
	checkUnhealthy = "unhealthy"
	readyTimeout   = 5 * time.Second
)

// errNotConfigured marks a dependency the handler was wired without.
var errNotConfigured = errors.New("not configured")

// HealthHandler serves the liveness and readiness probes.
type HealthHandler struct {
	db      *gorm.DB
	rdb     *redis.Client
	version string
}

// NewHealthHandler creates a HealthHandler; version is reported by the liveness probe.
func NewHealthHandler(db *gorm.DB, rdb *redis.Client, version string) *HealthHandler {
	return &HealthHandler{db: db, rdb: rdb, version: version}
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

	checks := map[string]Check{
		"database": h.check(c, "database", h.pingDB(ctx)),
		"redis":    h.check(c, "redis", h.pingRedis(ctx)),
	}
	status, code := healthOK, http.StatusOK
	for _, chk := range checks {
		if chk.Status != checkHealthy {
			status, code = healthDegraded, http.StatusServiceUnavailable
			break
		}
	}
	c.JSON(code, ReadyResponse{Status: status, Checks: checks})
}

// check renders the outcome of pinging name. The cause is attached to the gin context for the
// access log and replaced by a generic message in the response.
func (h *HealthHandler) check(c *gin.Context, name string, err error) Check {
	if err == nil {
		return Check{Status: checkHealthy}
	}
	_ = c.Error(fmt.Errorf("%s check: %w", name, err))
	return Check{Status: checkUnhealthy, Message: name + " is unavailable"}
}

// pingDB verifies the database connection.
func (h *HealthHandler) pingDB(ctx context.Context) error {
	if h.db == nil {
		return errNotConfigured
	}
	sqlDB, err := h.db.DB()
	if err != nil {
		return err
	}
	return sqlDB.PingContext(ctx)
}

// pingRedis verifies the Redis connection.
func (h *HealthHandler) pingRedis(ctx context.Context) error {
	if h.rdb == nil {
		return errNotConfigured
	}
	return h.rdb.Ping(ctx).Err()
}
