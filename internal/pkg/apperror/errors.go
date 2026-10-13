// Package apperror defines the structured error that crosses layer boundaries: a machine
// readable code, a client-safe message, the HTTP status it maps to and an optional cause that
// is never serialized.
package apperror

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes sent to clients.
const (
	CodeNotFound           = "NOT_FOUND"
	CodeValidation         = "VALIDATION_ERROR"
	CodeUnauthorized       = "UNAUTHORIZED"
	CodeForbidden          = "FORBIDDEN"
	CodeConflict           = "CONFLICT"
	CodeInternal           = "INTERNAL_ERROR"
	CodeBadRequest         = "BAD_REQUEST"
	CodeTooManyRequests    = "TOO_MANY_REQUESTS"
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE"
)

// AppError is a structured application error. HTTPStatus and Err are never serialized.
type AppError struct {
	Code       string         `json:"code"`
	Message    string         `json:"message"`
	HTTPStatus int            `json:"-"`
	Details    map[string]any `json:"details,omitempty"`
	Err        error          `json:"-"`
}

// Error renders the code, the message and the cause when there is one.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the cause for errors.Is and errors.As.
func (e *AppError) Unwrap() error {
	return e.Err
}

// NotFound reports that the resource with the given id does not exist.
func NotFound(resource string, id any) *AppError {
	return &AppError{
		Code:       CodeNotFound,
		Message:    resource + " not found",
		HTTPStatus: http.StatusNotFound,
		Details: map[string]any{
			"resource": resource,
			"id":       id,
		},
	}
}

// ValidationError reports invalid input, with details describing the violations.
func ValidationError(message string, details map[string]any) *AppError {
	return &AppError{
		Code:       CodeValidation,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
		Details:    details,
	}
}

// Unauthorized reports a failed authentication; an empty message means "authentication required".
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

// Forbidden reports a denied access; an empty message means "access denied".
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

// Conflict reports that a resource with the same field value already exists.
func Conflict(resource, field string, value any) *AppError {
	return &AppError{
		Code:       CodeConflict,
		Message:    fmt.Sprintf("%s with this %s already exists", resource, field),
		HTTPStatus: http.StatusConflict,
		Details: map[string]any{
			"resource": resource,
			"field":    field,
			"value":    value,
		},
	}
}

// Internal reports a server-side failure, wrapping its cause when there is one.
func Internal(message string, err error) *AppError {
	return &AppError{
		Code:       CodeInternal,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
		Err:        err,
	}
}

// BadRequest reports a request the service cannot act on.
func BadRequest(message string) *AppError {
	return &AppError{
		Code:       CodeBadRequest,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
	}
}

// TooManyRequests reports an exceeded rate limit with the wait in seconds.
func TooManyRequests(message string, retryAfter int) *AppError {
	return &AppError{
		Code:       CodeTooManyRequests,
		Message:    message,
		HTTPStatus: http.StatusTooManyRequests,
		Details: map[string]any{
			"retry_after_seconds": retryAfter,
		},
	}
}

// ServiceUnavailable reports that a dependency the request needs is down.
func ServiceUnavailable(message string) *AppError {
	return &AppError{
		Code:       CodeServiceUnavailable,
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

// IsAppError reports whether err is or wraps an AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// AsAppError returns the AppError that err is or wraps, and whether there is one.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// FromError returns the AppError that err is or wraps, a generic internal error for any other
// error, and nil for a nil error.
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}
	if appErr, ok := AsAppError(err); ok {
		return appErr
	}
	return Internal("an unexpected error occurred", err)
}
