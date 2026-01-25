package apperror

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAppError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *AppError
		expected string
	}{
		{
			name: "without wrapped error",
			err: &AppError{
				Code:    CodeNotFound,
				Message: "user not found",
			},
			expected: "NOT_FOUND: user not found",
		},
		{
			name: "with wrapped error",
			err: &AppError{
				Code:    CodeInternal,
				Message: "database error",
				Err:     errors.New("connection refused"),
			},
			expected: "INTERNAL_ERROR: database error: connection refused",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.err.Error())
		})
	}
}

func TestAppError_Unwrap(t *testing.T) {
	wrappedErr := errors.New("original error")
	appErr := &AppError{
		Code:    CodeInternal,
		Message: "wrapped",
		Err:     wrappedErr,
	}

	assert.Equal(t, wrappedErr, appErr.Unwrap())
	assert.True(t, errors.Is(appErr, wrappedErr))
}

func TestAppError_WithDetails(t *testing.T) {
	appErr := &AppError{
		Code:    CodeValidation,
		Message: "validation failed",
	}

	details := map[string]interface{}{
		"field": "email",
		"error": "invalid format",
	}

	result := appErr.WithDetails(details)

	assert.Same(t, appErr, result)
	assert.Equal(t, details, appErr.Details)
}

func TestAppError_WithError(t *testing.T) {
	appErr := &AppError{
		Code:    CodeInternal,
		Message: "something went wrong",
	}

	wrappedErr := errors.New("underlying cause")
	result := appErr.WithError(wrappedErr)

	assert.Same(t, appErr, result)
	assert.Equal(t, wrappedErr, appErr.Err)
}

func TestNew(t *testing.T) {
	appErr := New("CUSTOM_CODE", "custom message", http.StatusTeapot)

	assert.Equal(t, "CUSTOM_CODE", appErr.Code)
	assert.Equal(t, "custom message", appErr.Message)
	assert.Equal(t, http.StatusTeapot, appErr.HTTPStatus)
	assert.Nil(t, appErr.Details)
	assert.Nil(t, appErr.Err)
}

func TestNotFound(t *testing.T) {
	appErr := NotFound("user", 123)

	assert.Equal(t, CodeNotFound, appErr.Code)
	assert.Equal(t, "user not found", appErr.Message)
	assert.Equal(t, http.StatusNotFound, appErr.HTTPStatus)
	assert.Equal(t, "user", appErr.Details["resource"])
	assert.Equal(t, 123, appErr.Details["id"])
}

func TestValidationError(t *testing.T) {
	details := map[string]interface{}{
		"email": "invalid format",
	}
	appErr := ValidationError("validation failed", details)

	assert.Equal(t, CodeValidation, appErr.Code)
	assert.Equal(t, "validation failed", appErr.Message)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
	assert.Equal(t, details, appErr.Details)
}

func TestUnauthorized(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "invalid token",
			expectedMessage: "invalid token",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "authentication required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appErr := Unauthorized(tt.message)

			assert.Equal(t, CodeUnauthorized, appErr.Code)
			assert.Equal(t, tt.expectedMessage, appErr.Message)
			assert.Equal(t, http.StatusUnauthorized, appErr.HTTPStatus)
		})
	}
}

func TestForbidden(t *testing.T) {
	tests := []struct {
		name            string
		message         string
		expectedMessage string
	}{
		{
			name:            "with custom message",
			message:         "insufficient permissions",
			expectedMessage: "insufficient permissions",
		},
		{
			name:            "with empty message",
			message:         "",
			expectedMessage: "access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			appErr := Forbidden(tt.message)

			assert.Equal(t, CodeForbidden, appErr.Code)
			assert.Equal(t, tt.expectedMessage, appErr.Message)
			assert.Equal(t, http.StatusForbidden, appErr.HTTPStatus)
		})
	}
}

func TestConflict(t *testing.T) {
	appErr := Conflict("user", "email", "test@example.com")

	assert.Equal(t, CodeConflict, appErr.Code)
	assert.Equal(t, "user with this email already exists", appErr.Message)
	assert.Equal(t, http.StatusConflict, appErr.HTTPStatus)
	assert.Equal(t, "user", appErr.Details["resource"])
	assert.Equal(t, "email", appErr.Details["field"])
	assert.Equal(t, "test@example.com", appErr.Details["value"])
}

func TestInternal(t *testing.T) {
	wrappedErr := errors.New("database connection lost")
	appErr := Internal("failed to process request", wrappedErr)

	assert.Equal(t, CodeInternal, appErr.Code)
	assert.Equal(t, "failed to process request", appErr.Message)
	assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
	assert.Equal(t, wrappedErr, appErr.Err)
}

func TestBadRequest(t *testing.T) {
	appErr := BadRequest("invalid JSON format")

	assert.Equal(t, CodeBadRequest, appErr.Code)
	assert.Equal(t, "invalid JSON format", appErr.Message)
	assert.Equal(t, http.StatusBadRequest, appErr.HTTPStatus)
}

func TestTooManyRequests(t *testing.T) {
	appErr := TooManyRequests("rate limit exceeded", 60)

	assert.Equal(t, CodeTooManyRequests, appErr.Code)
	assert.Equal(t, "rate limit exceeded", appErr.Message)
	assert.Equal(t, http.StatusTooManyRequests, appErr.HTTPStatus)
	assert.Equal(t, 60, appErr.Details["retry_after_seconds"])
}

func TestServiceUnavailable(t *testing.T) {
	appErr := ServiceUnavailable("database is down")

	assert.Equal(t, CodeServiceUnavailable, appErr.Code)
	assert.Equal(t, "database is down", appErr.Message)
	assert.Equal(t, http.StatusServiceUnavailable, appErr.HTTPStatus)
}

func TestIsAppError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{
			name:     "is AppError",
			err:      NotFound("user", 1),
			expected: true,
		},
		{
			name:     "wrapped AppError",
			err:      fmt.Errorf("wrapped: %w", NotFound("user", 1)),
			expected: true,
		},
		{
			name:     "not AppError",
			err:      errors.New("regular error"),
			expected: false,
		},
		{
			name:     "nil error",
			err:      nil,
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsAppError(tt.err))
		})
	}
}

func TestAsAppError(t *testing.T) {
	t.Run("is AppError", func(t *testing.T) {
		original := NotFound("user", 1)
		result, ok := AsAppError(original)

		require.True(t, ok)
		assert.Equal(t, original, result)
	})

	t.Run("wrapped AppError", func(t *testing.T) {
		original := NotFound("user", 1)
		wrapped := fmt.Errorf("wrapped: %w", original)
		result, ok := AsAppError(wrapped)

		require.True(t, ok)
		assert.Equal(t, original, result)
	})

	t.Run("not AppError", func(t *testing.T) {
		result, ok := AsAppError(errors.New("regular error"))

		assert.False(t, ok)
		assert.Nil(t, result)
	})

	t.Run("nil error", func(t *testing.T) {
		result, ok := AsAppError(nil)

		assert.False(t, ok)
		assert.Nil(t, result)
	})
}

func TestFromError(t *testing.T) {
	t.Run("nil error", func(t *testing.T) {
		result := FromError(nil)
		assert.Nil(t, result)
	})

	t.Run("already AppError", func(t *testing.T) {
		original := NotFound("user", 1)
		result := FromError(original)

		assert.Equal(t, original, result)
	})

	t.Run("regular error", func(t *testing.T) {
		regularErr := errors.New("something went wrong")
		result := FromError(regularErr)

		assert.Equal(t, CodeInternal, result.Code)
		assert.Equal(t, "an unexpected error occurred", result.Message)
		assert.Equal(t, http.StatusInternalServerError, result.HTTPStatus)
		assert.Equal(t, regularErr, result.Err)
	})

	t.Run("wrapped AppError", func(t *testing.T) {
		original := Unauthorized("token expired")
		wrapped := fmt.Errorf("auth failed: %w", original)
		result := FromError(wrapped)

		assert.Equal(t, original, result)
	})
}

func TestErrorCodes(t *testing.T) {
	assert.Equal(t, "NOT_FOUND", CodeNotFound)
	assert.Equal(t, "VALIDATION_ERROR", CodeValidation)
	assert.Equal(t, "UNAUTHORIZED", CodeUnauthorized)
	assert.Equal(t, "FORBIDDEN", CodeForbidden)
	assert.Equal(t, "CONFLICT", CodeConflict)
	assert.Equal(t, "INTERNAL_ERROR", CodeInternal)
	assert.Equal(t, "BAD_REQUEST", CodeBadRequest)
	assert.Equal(t, "TOO_MANY_REQUESTS", CodeTooManyRequests)
	assert.Equal(t, "SERVICE_UNAVAILABLE", CodeServiceUnavailable)
}
