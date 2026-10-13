// Package middleware provides HTTP middleware components for the Gin framework.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig holds security middleware configuration.
type SecurityConfig struct {
	// CORS settings
	AllowOrigins     []string // Allowed origins
	AllowMethods     []string // Allowed HTTP methods
	AllowHeaders     []string // Allowed request headers
	ExposeHeaders    []string // Headers exposed to client
	AllowCredentials bool     // Allow credentials
	MaxAge           int      // Preflight cache duration (seconds)

	// Security headers
	ContentSecurityPolicy   string // CSP header value
	XFrameOptions           string // X-Frame-Options header
	XContentTypeOptions     string // X-Content-Type-Options header
	XXSSProtection          string // X-XSS-Protection header
	ReferrerPolicy          string // Referrer-Policy header
	StrictTransportSecurity string // HSTS header
}

// DefaultSecurityConfig returns default security configuration.
// Suitable for development. Use ProductionSecurityConfig for production.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours

		ContentSecurityPolicy:   "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
	}
}

// ProductionSecurityConfig returns stricter security configuration for production.
func ProductionSecurityConfig(allowedOrigins []string) SecurityConfig {
	cfg := DefaultSecurityConfig()
	cfg.AllowOrigins = allowedOrigins
	cfg.ContentSecurityPolicy = "default-src 'none'"
	return cfg
}

// SecurityHeaders returns a middleware that adds security headers to responses.
//
// Headers added:
//   - X-Content-Type-Options: prevents MIME type sniffing
//   - X-Frame-Options: prevents clickjacking
//   - X-XSS-Protection: enables XSS filter
//   - Referrer-Policy: controls referrer information
//   - Content-Security-Policy: restricts resource loading
//   - Strict-Transport-Security: enforces HTTPS
func SecurityHeaders(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set security headers
		c.Header("X-Content-Type-Options", config.XContentTypeOptions)
		c.Header("X-Frame-Options", config.XFrameOptions)
		c.Header("X-XSS-Protection", config.XXSSProtection)
		c.Header("Referrer-Policy", config.ReferrerPolicy)

		// Only set CSP for non-Swagger paths (Swagger needs inline scripts)
		if !strings.HasPrefix(c.Request.URL.Path, "/swagger") {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// HSTS only for HTTPS connections
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", config.StrictTransportSecurity)
		}

		c.Next()
	}
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
//
// Handles preflight OPTIONS requests and sets appropriate CORS headers.
func CORS(config SecurityConfig) gin.HandlerFunc {
	allowAllOrigins := len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*"

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Handle preflight requests
		if c.Request.Method == http.MethodOptions {
			switch {
			case allowAllOrigins:
				c.Header("Access-Control-Allow-Origin", "*")
			case isOriginAllowed(origin, config.AllowOrigins):
				c.Header("Access-Control-Allow-Origin", origin)
			default:
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
			c.Header("Access-Control-Max-Age", string(rune(config.MaxAge)))

			// Don't allow credentials with wildcard origin
			if config.AllowCredentials && !allowAllOrigins {
				c.Header("Access-Control-Allow-Credentials", "true")
			}

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Handle actual requests
		switch {
		case allowAllOrigins:
			c.Header("Access-Control-Allow-Origin", "*")
		case isOriginAllowed(origin, config.AllowOrigins):
			c.Header("Access-Control-Allow-Origin", origin)
			if config.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}

		// Expose headers to client
		if len(config.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
		}

		c.Next()
	}
}

// isOriginAllowed checks if the origin is in the allowed list.
func isOriginAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin || a == "*" {
			return true
		}
	}
	return false
}

// NoCache returns a middleware that adds cache-control headers to prevent caching.
// Use this for sensitive endpoints like authentication.
func NoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}
