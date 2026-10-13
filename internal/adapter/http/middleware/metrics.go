// Package middleware provides HTTP middleware components for the Gin framework.
package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Prometheus metrics for HTTP requests.
var (
	// httpRequestsTotal counts total HTTP requests by method, path, and status.
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_http_requests_total",
			Help: "Total number of HTTP requests",
		},
		[]string{"method", "path", "status"},
	)

	// httpRequestDuration measures HTTP request duration in seconds.
	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_http_request_duration_seconds",
			Help:    "HTTP request duration in seconds",
			Buckets: []float64{.005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5, 10},
		},
		[]string{"method", "path"},
	)

	// httpRequestsInFlight tracks current number of in-flight requests.
	httpRequestsInFlight = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "iam_http_requests_in_flight",
			Help: "Current number of HTTP requests being served",
		},
	)

	// authAttemptsTotal counts authentication attempts by result.
	authAttemptsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"result"},
	)

	// authzDecisionsTotal counts authorization decisions by result, resource, and action.
	authzDecisionsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_authz_decisions_total",
			Help: "Total number of authorization decisions",
		},
		[]string{"result", "resource", "action"},
	)

	// cacheHitsTotal counts cache operations by cache name and result (hit/miss).
	cacheHitsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_cache_hits_total",
			Help: "Total number of cache operations",
		},
		[]string{"cache", "result"},
	)

	// dbOperationsTotal counts database operations by operation type and table.
	dbOperationsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "iam_db_operations_total",
			Help: "Total number of database operations",
		},
		[]string{"operation", "table"},
	)

	// dbOperationDuration measures database operation duration in seconds.
	dbOperationDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "iam_db_operation_duration_seconds",
			Help:    "Database operation duration in seconds",
			Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
		},
		[]string{"operation", "table"},
	)
)

// Metrics returns a middleware that records Prometheus metrics for HTTP requests.
//
// Records request count, duration, and in-flight requests.
func Metrics() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = "unknown" // Unknown route
		}

		// Increment in-flight counter
		httpRequestsInFlight.Inc()
		defer httpRequestsInFlight.Dec()

		c.Next()

		// Record metrics after request completion
		status := strconv.Itoa(c.Writer.Status())
		duration := time.Since(start).Seconds()

		httpRequestsTotal.WithLabelValues(c.Request.Method, path, status).Inc()
		httpRequestDuration.WithLabelValues(c.Request.Method, path).Observe(duration)
	}
}

// RecordAuthAttempt records an authentication attempt in metrics.
func RecordAuthAttempt(success bool) {
	result := "failure"
	if success {
		result = "success"
	}
	authAttemptsTotal.WithLabelValues(result).Inc()
}

// RecordAuthzDecision records an authorization decision in metrics.
func RecordAuthzDecision(allowed bool, resource, action string) {
	result := "denied"
	if allowed {
		result = "allowed"
	}
	authzDecisionsTotal.WithLabelValues(result, resource, action).Inc()
}

// RecordCacheHit records a cache operation result in metrics.
func RecordCacheHit(cacheName string, hit bool) {
	result := "miss"
	if hit {
		result = "hit"
	}
	cacheHitsTotal.WithLabelValues(cacheName, result).Inc()
}

// RecordDBOperation records a database operation in metrics.
func RecordDBOperation(operation, table string, duration time.Duration) {
	dbOperationsTotal.WithLabelValues(operation, table).Inc()
	dbOperationDuration.WithLabelValues(operation, table).Observe(duration.Seconds())
}
