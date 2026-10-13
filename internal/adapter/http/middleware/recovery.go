package middleware

import (
	"errors"
	"fmt"
	"net/http"
	"runtime/debug"
	"syscall"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Recovery turns a panic in a handler into a logged error with its stack and a 500 response
// in the standard envelope. A panic caused by the client closing the connection is only logged.
func Recovery(log *logger.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			r := recover()
			if r == nil {
				return
			}

			l := log.FromContext(c.Request.Context())
			if isConnectionLost(r) {
				l.Warn("connection lost while handling request",
					"method", c.Request.Method, "path", c.Request.URL.Path, "reason", fmt.Sprint(r))
				c.Abort()
				return
			}

			l.Error("panic recovered",
				"method", c.Request.Method, "path", c.Request.URL.Path,
				"panic", fmt.Sprint(r), "stack", string(debug.Stack()))
			if !c.Writer.Written() {
				response.ErrorWithStatus(c, http.StatusInternalServerError, apperror.CodeInternal, "internal server error", nil)
			}
			c.Abort()
		}()
		c.Next()
	}
}

// isConnectionLost reports whether a recovered value means the client went away, in which
// case no response can be written and no stack trace is worth logging.
func isConnectionLost(r any) bool {
	err, ok := r.(error)
	if !ok {
		return false
	}
	return errors.Is(err, http.ErrAbortHandler) ||
		errors.Is(err, syscall.EPIPE) ||
		errors.Is(err, syscall.ECONNRESET)
}
