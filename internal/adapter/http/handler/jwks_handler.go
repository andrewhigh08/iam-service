package handler

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// JWKSHandler publishes the public signing keys.
type JWKSHandler struct {
	auth port.AuthService
}

// NewJWKSHandler creates a JWKSHandler.
func NewJWKSHandler(auth port.AuthService) *JWKSHandler {
	return &JWKSHandler{auth: auth}
}

// JWKS handles GET /.well-known/jwks.json. The body is the RFC 7517 key set itself, not the envelope.
// @Summary Public signing keys
// @Description Returns the JSON Web Key Set (RFC 7517) needed to verify access tokens.
// @Tags auth
// @Produce json
// @Success 200 {object} map[string]any
// @Failure 500 {object} response.APIResponse
// @Router /.well-known/jwks.json [get]
func (h *JWKSHandler) JWKS(c *gin.Context) {
	jwks, err := h.auth.PublicJWKS()
	if err != nil {
		response.Error(c, err)
		return
	}
	c.Data(http.StatusOK, "application/json", jwks)
}
