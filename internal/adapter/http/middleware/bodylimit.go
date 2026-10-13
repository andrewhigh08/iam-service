package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// DefaultBodyLimit is the request body size the router applies when none is configured.
const DefaultBodyLimit int64 = 1 << 20

// BodyLimit caps the request body at limit bytes. Reading past the limit fails with
// *http.MaxBytesError, which handlers answer with 413, and closes the connection.
func BodyLimit(limit int64) gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Body != nil && c.Request.Body != http.NoBody {
			c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, limit)
		}
		c.Next()
	}
}
