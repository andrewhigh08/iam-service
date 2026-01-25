// Package handler provides HTTP request handlers for the IAM service.
// Пакет handler предоставляет обработчики HTTP запросов для IAM сервиса.
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
// HealthHandler обрабатывает эндпоинты проверки здоровья.
//
// Provides liveness and readiness probes for Kubernetes.
// Предоставляет liveness и readiness пробы для Kubernetes.
type HealthHandler struct {
	db    *gorm.DB      // Database connection / Подключение к БД
	redis *redis.Client // Redis connection / Подключение к Redis
}

// NewHealthHandler creates a new HealthHandler instance.
// NewHealthHandler создаёт новый экземпляр HealthHandler.
func NewHealthHandler(db *gorm.DB, redis *redis.Client) *HealthHandler {
	return &HealthHandler{
		db:    db,
		redis: redis,
	}
}

// HealthStatus represents the health status response.
// HealthStatus представляет ответ о состоянии здоровья.
type HealthStatus struct {
	Status    string           `json:"status"`           // Overall status (ok/degraded) / Общий статус (ok/degraded)
	Timestamp string           `json:"timestamp"`        // Check timestamp / Время проверки
	Checks    map[string]Check `json:"checks,omitempty"` // Individual checks / Отдельные проверки
}

// Check represents an individual health check result.
// Check представляет результат отдельной проверки здоровья.
type Check struct {
	Status  string `json:"status"`            // Check status (healthy/unhealthy) / Статус проверки
	Message string `json:"message,omitempty"` // Error message if unhealthy / Сообщение об ошибке
}

// Live handles GET /health/live.
// Live обрабатывает GET /health/live.
//
// Liveness probe - checks if the service is running.
// Liveness проба - проверяет, запущен ли сервис.
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
// Ready обрабатывает GET /health/ready.
//
// Readiness probe - checks if the service is ready to accept requests.
// Readiness проба - проверяет, готов ли сервис принимать запросы.
// Verifies database and Redis connections.
// Проверяет подключения к БД и Redis.
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

	// Check database with timeout / Проверяем БД с таймаутом
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

	// Check Redis / Проверяем Redis
	if h.redis != nil {
		if err := h.redis.Ping(ctx).Err(); err != nil {
			checks["redis"] = Check{Status: "unhealthy", Message: err.Error()}
			allHealthy = false
		} else {
			checks["redis"] = Check{Status: "healthy"}
		}
	}

	// Determine overall status / Определяем общий статус
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
// Health обрабатывает GET /health (устаревший эндпоинт).
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
