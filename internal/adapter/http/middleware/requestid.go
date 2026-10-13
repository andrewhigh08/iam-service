package middleware

import (
	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

const (
	// RequestIDHeader carries the request id in requests and responses.
	RequestIDHeader = "X-Request-ID"
	// RequestIDKey is the gin context key holding the request id.
	RequestIDKey = "request_id"
)

// requestIDPattern is what a client-supplied request id must match to be accepted.
var requestIDPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// RequestID assigns every request an id: the client's X-Request-ID when it is 1 to 128
// characters of [A-Za-z0-9._-], otherwise a new UUID. The id is echoed in the response
// header and stored in the gin and request contexts.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(RequestIDHeader)
		if !requestIDPattern.MatchString(id) {
			id = uuid.NewString()
		}

		c.Set(RequestIDKey, id)
		c.Request = c.Request.WithContext(logger.WithRequestIDContext(c.Request.Context(), id))
		c.Header(RequestIDHeader, id)
		c.Next()
	}
}
