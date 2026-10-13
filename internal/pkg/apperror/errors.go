// Package apperror provides structured application error types.
//
// This package implements a consistent error handling pattern with:
// - Error codes for programmatic handling
// - Human-readable messages
// - HTTP status code mapping
// - Optional details and wrapped errors
package apperror

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes for different error types.
const (
	CodeNotFound           = "NOT_FOUND"           // Resource not found
	CodeValidation         = "VALIDATION_ERROR"    // Validation failed
	CodeUnauthorized       = "UNAUTHORIZED"        // Authentication required
	CodeForbidden          = "FORBIDDEN"           // Access denied
	CodeConflict           = "CONFLICT"            // Resource conflict
	CodeInternal           = "INTERNAL_ERROR"      // Internal server error
	CodeBadRequest         = "BAD_REQUEST"         // Invalid request
	CodeTooManyRequests    = "TOO_MANY_REQUESTS"   // Rate limit exceeded
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE" // Service unavailable
	CodePasswordExpired    = "PASSWORD_EXPIRED"    // Password has expired
)

// AppError represents a structured application error.
//
// Fields:
//   - Code: Machine-readable error code
//   - Message: Human-readable error message
//   - HTTPStatus: Corresponding HTTP status code
//   - Details: Additional error details
//   - Err: Wrapped underlying error
type AppError struct {
	Code       string                 `json:"code"`              // Error code
	Message    string                 `json:"message"`           // Error message
	HTTPStatus int                    `json:"-"`                 // HTTP status
	Details    map[string]interface{} `json:"details,omitempty"` // Additional details
	Err        error                  `json:"-"`                 // Wrapped error
}

// Error implements the error interface.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error for errors.Is/As support.
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error and returns the modified error.
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithError wraps an underlying error and returns the modified error.
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// New creates a new AppError with the specified code, message, and HTTP status.
func New(code, message string, httpStatus int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// NotFound creates a not found error for a specific resource.
func NotFound(resource string, id interface{}) *AppError {
	return &AppError{
		Code:       CodeNotFound,
		Message:    fmt.Sprintf("%s not found", resource),
		HTTPStatus: http.StatusNotFound,
		Details: map[string]interface{}{
			"resource": resource,
			"id":       id,
		},
	}
}

// ValidationError creates a validation error with details.
func ValidationError(message string, details map[string]interface{}) *AppError {
	return &AppError{
		Code:       CodeValidation,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
		Details:    details,
	}
}

// Unauthorized creates an authentication error.
func Unauthorized(message string) *AppError {
	if message == "" {
		message = "authentication required"
	}
	return &AppError{
		Code:       CodeUnauthorized,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
	}
}

// Forbidden creates an authorization/access denied error.
func Forbidden(message string) *AppError {
	if message == "" {
		message = "access denied"
	}
	return &AppError{
		Code:       CodeForbidden,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
	}
}

// Conflict creates a resource conflict error (e.g., duplicate entry).
func Conflict(resource, field string, value interface{}) *AppError {
	return &AppError{
		Code:       CodeConflict,
		Message:    fmt.Sprintf("%s with this %s already exists", resource, field),
		HTTPStatus: http.StatusConflict,
		Details: map[string]interface{}{
			"resource": resource,
			"field":    field,
			"value":    value,
		},
	}
}

// Internal creates an internal server error with an optional wrapped error.
func Internal(message string, err error) *AppError {
	return &AppError{
		Code:       CodeInternal,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
		Err:        err,
	}
}

// BadRequest creates a bad request error.
func BadRequest(message string) *AppError {
	return &AppError{
		Code:       CodeBadRequest,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
	}
}

// TooManyRequests creates a rate limit exceeded error.
func TooManyRequests(message string, retryAfter int) *AppError {
	return &AppError{
		Code:       CodeTooManyRequests,
		Message:    message,
		HTTPStatus: http.StatusTooManyRequests,
		Details: map[string]interface{}{
			"retry_after_seconds": retryAfter, // Retry after X seconds
		},
	}
}

// ServiceUnavailable creates a service unavailable error.
func ServiceUnavailable(message string) *AppError {
	return &AppError{
		Code:       CodeServiceUnavailable,
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

// PasswordExpired creates a password expired error.
func PasswordExpired(userID int64) *AppError {
	return &AppError{
		Code:       CodePasswordExpired,
		Message:    "password has expired and must be changed",
		HTTPStatus: http.StatusForbidden,
		Details: map[string]interface{}{
			"user_id":                 userID,
			"require_password_change": true,
		},
	}
}

// IsAppError checks if an error is an AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// AsAppError converts an error to AppError if possible.
// Returns the AppError and true if successful, nil and false otherwise.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// FromError wraps a generic error as an internal AppError.
// If the error is already an AppError, it returns it as-is.
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}
	if appErr, ok := AsAppError(err); ok {
		return appErr
	}
	return Internal("an unexpected error occurred", err)
}
