// Package handler provides HTTP request handlers for the IAM service.
package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsHandler handles Prometheus metrics endpoint.
//
// Exposes application metrics for Prometheus scraping.
type MetricsHandler struct{}

// NewMetricsHandler creates a new MetricsHandler instance.
func NewMetricsHandler() *MetricsHandler {
	return &MetricsHandler{}
}

// Metrics handles GET /metrics for Prometheus scraping.
//
// Returns metrics in Prometheus text format.
func (h *MetricsHandler) Metrics() gin.HandlerFunc {
	handler := promhttp.Handler()
	return func(c *gin.Context) {
		handler.ServeHTTP(c.Writer, c.Request)
	}
}

// RegisterMetrics registers the /metrics endpoint on the router.
func RegisterMetrics(router *gin.Engine) {
	handler := NewMetricsHandler()
	router.GET("/metrics", handler.Metrics())
}
