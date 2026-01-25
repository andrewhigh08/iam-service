// Package handler provides HTTP request handlers for the IAM service.
// Пакет handler предоставляет обработчики HTTP запросов для IAM сервиса.
package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler handles Prometheus metrics endpoint.
// MetricsHandler обрабатывает эндпоинт метрик Prometheus.
//
// Exposes application metrics for Prometheus scraping.
// Предоставляет метрики приложения для сбора Prometheus.
type MetricsHandler struct{}

// NewMetricsHandler creates a new MetricsHandler instance.
// NewMetricsHandler создаёт новый экземпляр MetricsHandler.
func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

// Metrics handles GET /metrics for Prometheus scraping.
// Metrics обрабатывает GET /metrics для сбора данных Prometheus.
//
// Returns metrics in Prometheus text format.
// Возвращает метрики в текстовом формате Prometheus.
func (h *MetricsHandler) Metrics() gin.HandlerFunc {
	handler := promhttp.Handler()
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// RegisterMetrics registers the /metrics endpoint on the router.
// RegisterMetrics регистрирует эндпоинт /metrics на маршрутизаторе.
func RegisterMetrics(router *gin.Engine) {
	handler := NewMetricsHandler()
	router.GET("/metrics", handler.Metrics())
}
