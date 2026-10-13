package handler

import (
	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// RegisterMetrics serves the Prometheus text exposition of the default registry at /metrics.
func RegisterMetrics(router *gin.Engine) {
	router.GET("/metrics", gin.WrapH(promhttp.Handler()))
}
