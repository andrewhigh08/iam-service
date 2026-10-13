package handler

import (
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRegisterMetrics_ServesPrometheusText(t *testing.T) {
	t.Parallel()
	r := gin.New()
	RegisterMetrics(r)

	rec := serve(r, newRequest(t, http.MethodGet, "/metrics", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	assert.Contains(t, rec.Body.String(), "go_goroutines")
}
