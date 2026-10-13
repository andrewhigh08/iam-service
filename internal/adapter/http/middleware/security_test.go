package middleware

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityHeaders(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name           string
		path           string
		forwardedProto string
		tls            bool
		wantCSP        bool
		wantNoStore    bool
		wantHSTS       bool
	}{
		{name: "auth endpoints get CSP and no-store", path: "/auth/login", wantCSP: true, wantNoStore: true},
		{name: "api endpoints get CSP and no-store", path: "/api/v1/users", wantCSP: true, wantNoStore: true},
		{name: "health endpoints get CSP but stay cacheable", path: "/health/live", wantCSP: true},
		{name: "swagger ui skips CSP", path: "/swagger/index.html"},
		{name: "swagger root skips CSP", path: "/swagger"},
		{name: "a path merely starting with swagger keeps CSP", path: "/swaggerx", wantCSP: true},
		{name: "HSTS with X-Forwarded-Proto https", path: "/auth/login", forwardedProto: "https", wantCSP: true, wantNoStore: true, wantHSTS: true},
		{name: "no HSTS with X-Forwarded-Proto http", path: "/auth/login", forwardedProto: "http", wantCSP: true, wantNoStore: true},
		{name: "HSTS over TLS", path: "/health/live", tls: true, wantCSP: true, wantHSTS: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := gin.New()
			r.Use(SecurityHeaders())
			r.GET(tt.path, okHandler)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, tt.path, http.NoBody)
			if tt.forwardedProto != "" {
				req.Header.Set("X-Forwarded-Proto", tt.forwardedProto)
			}
			if tt.tls {
				req.TLS = &tls.ConnectionState{}
			}

			rec := serve(r, req)

			require.Equal(t, http.StatusOK, rec.Code)
			h := rec.Header()
			assert.Equal(t, "nosniff", h.Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", h.Get("X-Frame-Options"))
			assert.Equal(t, "no-referrer", h.Get("Referrer-Policy"))

			if tt.wantCSP {
				assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", h.Get("Content-Security-Policy"))
			} else {
				assert.Empty(t, h.Get("Content-Security-Policy"))
			}
			if tt.wantNoStore {
				assert.Equal(t, "no-store", h.Get("Cache-Control"))
			} else {
				assert.Empty(t, h.Get("Cache-Control"))
			}
			if tt.wantHSTS {
				assert.Equal(t, "max-age=31536000; includeSubDomains", h.Get("Strict-Transport-Security"))
			} else {
				assert.Empty(t, h.Get("Strict-Transport-Security"))
			}
		})
	}
}

func TestNewCORS_DisabledWithoutOrigins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		origins []string
	}{
		{"nil list", nil},
		{"empty list", []string{}},
		{"blank entries", []string{"", "   "}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw, err := NewCORS(tt.origins)

			require.NoError(t, err)
			assert.Nil(t, mw)
		})
	}
}

func TestNewCORS_RejectsInvalidOrigins(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		origins []string
	}{
		{"origin without a scheme", []string{"app.example.com"}},
		{"several wildcards", []string{"https://*.*.example.com"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			mw, err := NewCORS(tt.origins)

			require.ErrorContains(t, err, "invalid CORS origins")
			assert.Contains(t, err.Error(), tt.origins[0])
			assert.Nil(t, mw)
		})
	}
}

// corsRouter serves GET and POST /data behind the CORS middleware for origins.
func corsRouter(t *testing.T, origins []string) *gin.Engine {
	t.Helper()
	mw, err := NewCORS(origins)
	require.NoError(t, err)
	r := gin.New()
	r.Use(mw)
	r.GET("/data", okHandler)
	r.POST("/data", okHandler)
	return r
}

// corsRequest builds a request to /data carrying origin; method OPTIONS makes it a preflight for POST.
func corsRequest(t *testing.T, method, origin string) *http.Request {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), method, "/data", http.NoBody)
	req.Header.Set("Origin", origin)
	if method == http.MethodOptions {
		req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	}
	return req
}

func TestNewCORS_ExplicitOrigins(t *testing.T) {
	t.Parallel()
	const allowed = "https://app.example.com"
	r := corsRouter(t, []string{allowed, " https://*.trusted.example "})

	t.Run("preflight from an allowed origin", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodOptions, allowed))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		h := rec.Header()
		assert.Equal(t, allowed, h.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", h.Get("Access-Control-Allow-Credentials"))
		assert.Contains(t, h.Get("Access-Control-Allow-Methods"), http.MethodDelete)
		assert.Contains(t, h.Get("Access-Control-Allow-Headers"), "Authorization")
		assert.Contains(t, h.Get("Access-Control-Allow-Headers"), "X-Request-Id")
		assert.Equal(t, "43200", h.Get("Access-Control-Max-Age"))
	})

	t.Run("request from an allowed origin", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodGet, allowed))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
		h := rec.Header()
		assert.Equal(t, allowed, h.Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", h.Get("Access-Control-Allow-Credentials"))
		assert.Equal(t, "X-Request-Id", h.Get("Access-Control-Expose-Headers"))
		assert.Equal(t, "Origin", h.Get("Vary"))
	})

	t.Run("request matching a wildcard pattern", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodGet, "https://api.trusted.example"))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://api.trusted.example", rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("preflight from a disallowed origin", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodOptions, "https://evil.example"))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("request from a disallowed origin", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodGet, "https://evil.example"))

		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Empty(t, rec.Body.String(), "the handler never runs")
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("request without an origin is not a CORS request", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/data", http.NoBody))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
	})
}

func TestNewCORS_WildcardAllowsEveryOriginWithoutCredentials(t *testing.T) {
	t.Parallel()
	r := corsRouter(t, []string{"*"})

	t.Run("preflight", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodOptions, "https://anything.example"))

		assert.Equal(t, http.StatusNoContent, rec.Code)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("request", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, corsRequest(t, http.MethodGet, "https://anything.example"))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "ok", rec.Body.String())
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})
}

func TestHasPathPrefix(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path string
		want bool
	}{
		{"/swagger", true},
		{"/swagger/", true},
		{"/swagger/index.html", true},
		{"/swaggerx", false},
		{"/swag", false},
		{"/", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, hasPathPrefix(tt.path, "/swagger"))
		})
	}
}
