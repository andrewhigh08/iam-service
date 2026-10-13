package middleware

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// AccessLog writes one log line per request after it completes: method, route, status,
// duration_ms and client_ip, plus the request id, user id and trace ids found in the request
// context. Responses with a 5xx status are logged at Warn, everything else at Info. A request
// whose handler panics is logged as a 500 before the panic is passed on to Recovery.
func AccessLog(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		defer func() {
			status := c.Writer.Status()
			panicked := recover()
			if panicked != nil {
				status = http.StatusInternalServerError
				defer panic(panicked)
			}
			logRequest(log, c, status, time.Since(start), panicked != nil)
		}()
		c.Next()
	}
}

func logRequest(log *logger.Logger, c *gin.Context, status int, elapsed time.Duration, panicked bool) {
	route := c.FullPath()
	if route == "" {
		route = c.Request.URL.Path
	}
	attrs := []any{
		slog.String("method", c.Request.Method),
		slog.String("route", route),
		slog.Int("status", status),
		slog.Float64("duration_ms", float64(elapsed.Microseconds())/1e3),
		slog.String("client_ip", c.ClientIP()),
	}
	if panicked {
		attrs = append(attrs, slog.Bool("panic", true))
	}
	if len(c.Errors) > 0 {
		attrs = append(attrs, slog.Any("errors", c.Errors.Errors()))
	}

	l := log.FromContext(c.Request.Context())
	if status >= http.StatusInternalServerError {
		l.Warn("request completed", attrs...)
		return
	}
	l.Info("request completed", attrs...)
}
