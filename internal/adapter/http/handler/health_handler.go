// Package handler provides HTTP request handlers for the IAM service.
package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
)

// HealthHandler handles health check endpoints.
//
// Provides liveness and readiness probes for Kubernetes.
type HealthHandler struct {
	db    *gorm.DB      // Database connection
	redis *redis.Client // Redis connection
}

// NewHealthHandler creates a new HealthHandler instance.
func NewHealthHandler(db *gorm.DB, redis *redis.Client) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

// HealthStatus represents the health status response.
type HealthStatus struct {
	Status    string           `json:"status"`           // Overall status (ok/degraded)
	Timestamp string           `json:"timestamp"`        // Check timestamp
	Checks    map[string]Check `json:"checks,omitempty"` // Individual checks
}

// Check represents an individual health check result.
type Check struct {
	Status  string `json:"status"`            // Check status (healthy/unhealthy)
	Message string `json:"message,omitempty"` // Error message if unhealthy
}

// Live handles GET /health/live.
//
// Liveness probe - checks if the service is running.
// @Summary Liveness probe
// @Description Check if the service is alive
// @Tags health
// @Produce json
// @Success 200 {object} HealthStatus
// @Router /health/live [get]
func (h *HealthHandler) Live(c *gin.Context) {
	c.JSON(http.StatusOK, HealthStatus{
		Status:    "ok",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// Ready handles GET /health/ready.
//
// Readiness probe - checks if the service is ready to accept requests.
// Verifies database and Redis connections.
// @Summary Readiness probe
// @Description Check if the service is ready to accept requests
// @Tags health
// @Produce json
// @Success 200 {object} HealthStatus
// @Failure 503 {object} HealthStatus
// @Router /health/ready [get]
func (h *HealthHandler) Ready(c *gin.Context) {
	checks := make(map[string]Check)
	allHealthy := true

	// Check database with timeout
	ctx, cancel := context.WithTimeout(c.Request.Context(), 5*time.Second)
	defer cancel()

	sqlDB, err := h.db.DB()
	if err != nil {
		checks["database"] = Check{Status: "unhealthy", Message: err.Error()}
		allHealthy = false
	} else if err := sqlDB.PingContext(ctx); err != nil {
		checks["database"] = Check{Status: "unhealthy", Message: err.Error()}
		allHealthy = false
	} else {
		checks["database"] = Check{Status: "healthy"}
	}

	// Check Redis
	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = Check{Status: "unhealthy", Message: err.Error()}
			allHealthy = false
		} else {
			checks["redis"] = Check{Status: "healthy"}
		}
	}

	// Determine overall status
	status := "ok"
	httpStatus := http.StatusOK
	if !allHealthy {
		status = "degraded"
		httpStatus = http.StatusServiceUnavailable
	}

	c.JSON(httpStatus, HealthStatus{
		Status:    status,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Checks:    checks,
	})
}

// Health handles GET /health (legacy endpoint).
// @Summary Health check
// @Description Basic health check
// @Tags health
// @Produce json
// @Success 200 {object} response.APIResponse
// @Router /health [get]
func (h *HealthHandler) Health(c *gin.Context) {
	response.Success(c, gin.H{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	})
}
