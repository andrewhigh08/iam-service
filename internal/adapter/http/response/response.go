// Package response provides standardized API response structures and helpers.
//
// All API endpoints should use these helpers to ensure consistent response format.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// APIResponse represents a standardized API response structure.
//
// All API responses follow this format for consistency.
type APIResponse struct {
	Success bool       `json:"success"`         // Operation success flag
	Data    any        `json:"data,omitempty"`  // Response payload
	Error   *ErrorBody `json:"error,omitempty"` // Error details (if any)
	Meta    *Meta      `json:"meta,omitempty"`  // Pagination metadata
}

// ErrorBody represents the error details in an API response.
type ErrorBody struct {
	Code    string         `json:"code"`              // Machine-readable error code
	Message string         `json:"message"`           // Human-readable error message
	Details map[string]any `json:"details,omitempty"` // Additional error details
}

// Meta represents pagination metadata in API responses.
type Meta struct {
	Page       int   `json:"page"`        // Current page number
	PageSize   int   `json:"page_size"`   // Items per page
	Total      int64 `json:"total"`       // Total items count
	TotalPages int   `json:"total_pages"` // Total pages count
}

// Success sends a successful response with data.
func Success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// SuccessWithMeta sends a successful response with data and pagination metadata.
func SuccessWithMeta(c *gin.Context, data any, meta *Meta) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// Created sends a successful response for resource creation (HTTP 201).
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

// NoContent sends a successful response with no content (HTTP 204).
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends an error response from an AppError.
// Automatically determines HTTP status code based on error type.
func Error(c *gin.Context, err error) {
	appErr := apperror.FromError(err)

	c.JSON(appErr.HTTPStatus, APIResponse{
		Success: false,
		Error: &ErrorBody{
			Code:    appErr.Code,
			Message: appErr.Message,
			Details: appErr.Details,
		},
	})
}

// ErrorWithStatus sends an error response with a specific HTTP status.
func ErrorWithStatus(c *gin.Context, status int, code, message string, details map[string]any) {
	c.JSON(status, APIResponse{
		Success: false,
		Error: &ErrorBody{
			Code:    code,
			Message: message,
			Details: details,
		},
	})
}

// BadRequest sends a 400 Bad Request response.
func BadRequest(c *gin.Context, message string) {
	Error(c, apperror.BadRequest(message))
}

// Unauthorized sends a 401 Unauthorized response.
func Unauthorized(c *gin.Context, message string) {
	if message == "" {
		message = "authentication required"
	}
	Error(c, apperror.Unauthorized(message))
}

// Forbidden sends a 403 Forbidden response.
func Forbidden(c *gin.Context, message string) {
	if message == "" {
		message = "access denied"
	}
	Error(c, apperror.Forbidden(message))
}

// NotFound sends a 404 Not Found response.
func NotFound(c *gin.Context, resource string, id any) {
	Error(c, apperror.NotFound(resource, id))
}

// Conflict sends a 409 Conflict response.
func Conflict(c *gin.Context, resource, field string, value any) {
	Error(c, apperror.Conflict(resource, field, value))
}

// InternalError sends a 500 Internal Server Error response.
func InternalError(c *gin.Context, message string) {
	Error(c, apperror.Internal(message, nil))
}

// TooManyRequests sends a 429 Too Many Requests response.
func TooManyRequests(c *gin.Context, message string, retryAfter int) {
	c.Header("Retry-After", string(rune(retryAfter)))
	Error(c, apperror.TooManyRequests(message, retryAfter))
}

// ValidationError sends a 400 response for validation errors.
func ValidationError(c *gin.Context, message string, details map[string]any) {
	Error(c, apperror.ValidationError(message, details))
}

// NewMeta creates pagination metadata from given parameters.
func NewMeta(page, pageSize int, total int64) *Meta {
	totalPages := int(total) / pageSize
	if int(total)%pageSize > 0 {
		totalPages++
	}
	return &Meta{
		Page:       page,
		PageSize:   pageSize,
		Total:      total,
		TotalPages: totalPages,
	}
}
