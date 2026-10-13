package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/go-playground/validator/v10"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
)

// Validation errors name fields the way clients sent them: by their json tag.
func init() {
	if engine, ok := binding.Validator.Engine().(*validator.Validate); ok {
		engine.RegisterTagNameFunc(jsonFieldName)
	}
}

// jsonFieldName returns the JSON name of field, or "" to fall back to the Go name.
func jsonFieldName(field reflect.StructField) string {
	name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
	if name == "-" {
		return ""
	}
	return name
}

const (
	msgInvalidBody      = "invalid request body"
	codePayloadTooLarge = "PAYLOAD_TOO_LARGE"
)

// bindJSON decodes the JSON body into dst and reports whether it is valid.
// On failure the error response has already been written.
func bindJSON(c *gin.Context, dst any) bool {
	err := c.ShouldBindJSON(dst)
	if err == nil {
		return true
	}

	var (
		tooLarge  *http.MaxBytesError
		fieldErrs validator.ValidationErrors
		typeErr   *json.UnmarshalTypeError
	)
	switch {
	case errors.As(err, &tooLarge):
		response.ErrorWithStatus(c, http.StatusRequestEntityTooLarge, codePayloadTooLarge, "request body too large", nil)
	case errors.As(err, &fieldErrs):
		response.ValidationError(c, msgInvalidBody, map[string]any{"fields": fieldErrors(fieldErrs)})
	case errors.As(err, &typeErr) && typeErr.Field != "":
		response.ValidationError(c, msgInvalidBody, map[string]any{"fields": map[string]string{typeErr.Field: "invalid type"}})
	default:
		response.ValidationError(c, msgInvalidBody, map[string]any{"reason": "body must be a JSON object"})
	}
	return false
}

// fieldErrors maps each failed field, named as in JSON, to the rule it violated.
func fieldErrors(errs validator.ValidationErrors) map[string]string {
	fields := make(map[string]string, len(errs))
	for _, fe := range errs {
		rule := fe.Tag()
		if p := fe.Param(); p != "" {
			rule += "=" + p
		}
		fields[fe.Field()] = rule
	}
	return fields
}
