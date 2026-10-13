// Package middleware provides HTTP middleware components for the Gin framework.
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Constants for request ID handling.
const (
	// RequestIDHeader is the HTTP header name for request ID.
	RequestIDHeader = "X-Request-ID"

	// RequestIDKey is the context key for storing request ID.
	RequestIDKey = "request_id"
)

// RequestID returns a middleware that generates and sets a unique request ID.
//
// If the client provides X-Request-ID header, it will be used.
// Otherwise, a new UUID will be generated.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID is already provided by client
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in Gin context
		c.Set(RequestIDKey, requestID)

		// Add request ID to logger context for distributed tracing
		ctx := logger.WithRequestIDContext(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		// Set request ID in response header
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
}

// GetRequestID retrieves the request ID from Gin context.
// Returns empty string if request ID is not set.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		if strID, ok := id.(string); ok {
			return strID
		}
	}
	return ""
}
