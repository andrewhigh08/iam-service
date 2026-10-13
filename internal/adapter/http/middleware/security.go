package middleware

import (
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

const (
	contentSecurityPolicy   = "default-src 'none'; frame-ancestors 'none'"
	strictTransportSecurity = "max-age=31536000; includeSubDomains"
	corsMaxAge              = 12 * time.Hour
)

// SecurityHeaders sets the response headers that harden every endpoint: nosniff, DENY framing,
// no referrer, a deny-all CSP (except under /swagger, whose UI needs inline assets), no-store
// caching for /auth and /api, and HSTS when the request arrived over TLS.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")

		path := c.Request.URL.Path
		if !hasPathPrefix(path, "/swagger") {
			h.Set("Content-Security-Policy", contentSecurityPolicy)
		}
		if hasPathPrefix(path, "/auth") || hasPathPrefix(path, "/api") {
			h.Set("Cache-Control", "no-store")
		}
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			h.Set("Strict-Transport-Security", strictTransportSecurity)
		}
		c.Next()
	}
}

// NewCORS builds the CORS middleware for allowedOrigins and returns nil when the list is empty,
// in which case the caller leaves CORS disabled. "*" allows every origin without credentials;
// explicit origins (full scheme and host, one "*" wildcard allowed) are served with credentials.
// An origin the CORS library would reject is reported as an error instead of a panic.
func NewCORS(allowedOrigins []string) (gin.HandlerFunc, error) {
	origins := make([]string, 0, len(allowedOrigins))
	for _, o := range allowedOrigins {
		if o = strings.TrimSpace(o); o != "" {
			origins = append(origins, o)
		}
	}
	if len(origins) == 0 {
		return nil, nil
	}

	for _, o := range origins {
		if err := validateOrigin(o); err != nil {
			return nil, fmt.Errorf("invalid CORS origins %q: %w", origins, err)
		}
	}
	wildcard := slices.Contains(origins, "*")
	cfg := cors.Config{
		AllowOrigins:     origins,
		AllowWildcard:    !wildcard,
		AllowMethods:     []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodDelete, http.MethodOptions},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", RequestIDHeader},
		ExposeHeaders:    []string{RequestIDHeader},
		AllowCredentials: !wildcard,
		MaxAge:           corsMaxAge,
	}
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid CORS origins %q: %w", origins, err)
	}
	return cors.New(cfg), nil
}

// validateOrigin rejects the origins the CORS library would panic on: anything but "*" must
// carry an http or https scheme and may hold at most one wildcard.
func validateOrigin(origin string) error {
	switch {
	case origin == "*":
		return nil
	case !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://"):
		return fmt.Errorf("origin %q must start with http:// or https://", origin)
	case strings.Count(origin, "*") > 1:
		return fmt.Errorf("origin %q may contain at most one wildcard", origin)
	}
	return nil
}

func hasPathPrefix(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, prefix+"/")
}
