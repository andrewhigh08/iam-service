package handler

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	// Registers the generated OpenAPI document served at /swagger/doc.json.
	_ "github.com/andrewhigh08/iam-service/docs"
)

func TestRegisterSwagger_ServesTheUIAndTheSpec(t *testing.T) {
	t.Parallel()
	r := gin.New()
	RegisterSwagger(r)

	t.Run("ui", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, newRequest(t, http.MethodGet, "/swagger/index.html", nil))

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), "swagger")
	})

	t.Run("spec", func(t *testing.T) {
		t.Parallel()
		rec := serve(r, newRequest(t, http.MethodGet, "/swagger/doc.json", nil))

		require.Equal(t, http.StatusOK, rec.Code)
		var spec struct {
			Paths map[string]any `json:"paths"`
		}
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &spec))
		assert.Contains(t, spec.Paths, "/auth/login")
		assert.Contains(t, spec.Paths, "/api/v1/users/{id}/block")
	})
}
