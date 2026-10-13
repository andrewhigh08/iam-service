package integration

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHealthMetricsAndSwaggerEndpoints(t *testing.T) {
	t.Parallel()
	c := newClient(t)

	live := c.do(t, http.MethodGet, "/health/live", nil, "")
	requireStatus(t, live, http.StatusOK)
	assert.JSONEq(t, `{"status":"ok","version":"`+appVersion+`"}`, string(live.Body))

	ready := c.do(t, http.MethodGet, "/health/ready", nil, "")
	requireStatus(t, ready, http.StatusOK)
	var readiness struct {
		Status string `json:"status"`
		Checks map[string]struct {
			Status  string `json:"status"`
			Message string `json:"message"`
		} `json:"checks"`
	}
	require.NoError(t, json.Unmarshal(ready.Body, &readiness))
	assert.Equal(t, "ok", readiness.Status)
	require.Len(t, readiness.Checks, 2)
	for _, name := range []string{"database", "redis"} {
		require.Contains(t, readiness.Checks, name)
		assert.Equalf(t, "healthy", readiness.Checks[name].Status, "check %s", name)
		assert.Empty(t, readiness.Checks[name].Message)
	}

	metrics := c.do(t, http.MethodGet, "/metrics", nil, "")
	requireStatus(t, metrics, http.StatusOK)
	for _, metric := range []string{"iam_http_requests_total", "iam_http_request_duration_seconds", "iam_http_requests_in_flight", "iam_auth_attempts_total"} {
		assert.Contains(t, string(metrics.Body), metric)
	}

	swagger := c.do(t, http.MethodGet, "/swagger/index.html", nil, "")
	requireStatus(t, swagger, http.StatusOK)
	assert.Contains(t, strings.ToLower(string(swagger.Body)), "swagger")
	doc := c.do(t, http.MethodGet, "/swagger/doc.json", nil, "")
	requireStatus(t, doc, http.StatusOK)
	assert.Contains(t, string(doc.Body), "/auth/login")
}

func TestSecurityHeadersAndRequestID(t *testing.T) {
	t.Parallel()
	c := newClient(t)

	resp := c.do(t, http.MethodGet, "/health/live", nil, "")
	requireStatus(t, resp, http.StatusOK)
	assert.Equal(t, "nosniff", resp.Header.Get("X-Content-Type-Options"))
	assert.Equal(t, "DENY", resp.Header.Get("X-Frame-Options"))
	assert.Equal(t, "no-referrer", resp.Header.Get("Referrer-Policy"))
	assert.Equal(t, "default-src 'none'; frame-ancestors 'none'", resp.Header.Get("Content-Security-Policy"))
	assert.Empty(t, resp.Header.Get("Cache-Control"))
	assert.Empty(t, resp.Header.Get("Strict-Transport-Security"))
	_, err := uuid.Parse(resp.Header.Get("X-Request-ID"))
	require.NoError(t, err, "a generated request id is a UUID")

	// Auth and API answers are never cached; a well-formed client request id is echoed.
	req := c.newRequest(t, http.MethodPost, "/auth/login", map[string]string{})
	req.Header.Set("X-Request-ID", "client-id.123")
	login := c.send(t, req)
	requireStatus(t, login, http.StatusBadRequest)
	assert.Equal(t, "no-store", login.Header.Get("Cache-Control"))
	assert.Equal(t, "client-id.123", login.Header.Get("X-Request-ID"))

	req = c.newRequest(t, http.MethodGet, "/api/v1/sessions", nil)
	req.Header.Set("X-Request-ID", "not valid!")
	api := c.send(t, req)
	requireStatus(t, api, http.StatusUnauthorized)
	assert.Equal(t, "no-store", api.Header.Get("Cache-Control"))
	_, err = uuid.Parse(api.Header.Get("X-Request-ID"))
	require.NoError(t, err, "a malformed client request id is replaced")

	// The Swagger UI needs inline assets, so it is served without the CSP.
	swagger := c.do(t, http.MethodGet, "/swagger/index.html", nil, "")
	requireStatus(t, swagger, http.StatusOK)
	assert.Empty(t, swagger.Header.Get("Content-Security-Policy"))

	// HSTS is added when a proxy reports that the request arrived over TLS.
	req = c.newRequest(t, http.MethodGet, "/health/live", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	assert.Equal(t, "max-age=31536000; includeSubDomains", c.send(t, req).Header.Get("Strict-Transport-Security"))
}

func TestOversizedBodyIsRejected(t *testing.T) {
	t.Parallel()
	c := newClient(t)

	body := rawBody(`{"email":"` + strings.Repeat("a", 1<<20) + `@example.com","password":"x"}`)
	resp := c.do(t, http.MethodPost, "/auth/login", body, "")
	requireStatus(t, resp, http.StatusRequestEntityTooLarge)
	require.NotNil(t, resp.Error)
	assert.Equal(t, "PAYLOAD_TOO_LARGE", resp.Error.Code)
	assert.Equal(t, "request body too large", resp.Error.Message)
}
