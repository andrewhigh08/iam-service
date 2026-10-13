package handler

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/middleware"
)

func TestFieldErrors_UsesJSONNames(t *testing.T) {
	t.Parallel()
	type probe struct {
		Email    string `json:"email" binding:"required,email"`
		PageSize int    `json:"page_size,omitempty" binding:"max=100"`
		Agent    string `json:"ua" binding:"required"`
		Role     string `json:"role" binding:"oneof=admin viewer"`
		Untagged string `binding:"required"`
	}
	err := binding.Validator.ValidateStruct(probe{Email: "nope", PageSize: 500, Role: "root"})
	var errs validator.ValidationErrors
	require.ErrorAs(t, err, &errs)

	assert.Equal(t, map[string]string{
		"email":     "email",
		"page_size": "max=100",
		"ua":        "required",
		"role":      "oneof=admin viewer",
		"Untagged":  "required",
	}, fieldErrors(errs))
}

func TestBindJSON_MapsAnOversizedBodyTo413(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	r := gin.New()
	r.POST("/auth/login", middleware.BodyLimit(64), f.h.Login)
	body := `{"email":"user@example.com","password":"` + strings.Repeat("x", 100) + `"}`

	rec := serve(r, newRequest(t, http.MethodPost, "/auth/login", body))

	errBody := assertError(t, rec, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large")
	assert.Nil(t, errBody.Details)
}
