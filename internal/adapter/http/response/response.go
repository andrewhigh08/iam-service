// Package response defines the JSON envelope shared by every endpoint and the helpers that write it.
package response

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// APIResponse is the envelope of every JSON response.
type APIResponse struct {
	Success bool       `json:"success"`
	Data    any        `json:"data,omitempty"`
	Error   *ErrorBody `json:"error,omitempty"`
	Meta    *Meta      `json:"meta,omitempty"`
}

// ErrorBody describes why a request failed.
type ErrorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

// Meta carries pagination information.
type Meta struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// Success writes a 200 response with data.
func Success(c *gin.Context, data any) {
	c.JSON(http.StatusOK, APIResponse{Success: true, Data: data})
}

// SuccessWithMeta writes a 200 response with data and pagination metadata.
func SuccessWithMeta(c *gin.Context, data any, meta *Meta) {
	c.JSON(http.StatusOK, APIResponse{Success: true, Data: data, Meta: meta})
}

// Created writes a 201 response with data.
func Created(c *gin.Context, data any) {
	c.JSON(http.StatusCreated, APIResponse{Success: true, Data: data})
}

// Error writes err as an error response with the status of its AppError; any other error
// becomes a generic 500. Only the code, message and details are sent, never the wrapped cause.
// Server-side failures are also attached to the gin context so the access log can report them.
func Error(c *gin.Context, err error) {
	appErr := apperror.FromError(err)
	if appErr == nil {
		appErr = apperror.Internal("an unexpected error occurred", nil)
	}
	status := appErr.HTTPStatus
	if status < http.StatusContinue {
		status = http.StatusInternalServerError
	}
	if status >= http.StatusInternalServerError {
		_ = c.Error(appErr)
	}

	c.JSON(status, APIResponse{
		Success: false,
		Error:   &ErrorBody{Code: appErr.Code, Message: appErr.Message, Details: appErr.Details},
	})
}

// ErrorWithStatus writes an error response with an explicit status, code and message.
func ErrorWithStatus(c *gin.Context, status int, code, message string, details map[string]any) {
	c.JSON(status, APIResponse{
		Success: false,
		Error:   &ErrorBody{Code: code, Message: message, Details: details},
	})
}

// BadRequest writes a 400 response.
func BadRequest(c *gin.Context, message string) {
	Error(c, apperror.BadRequest(message))
}

// Unauthorized writes a 401 response; an empty message becomes "authentication required".
func Unauthorized(c *gin.Context, message string) {
	Error(c, apperror.Unauthorized(message))
}

// Forbidden writes a 403 response; an empty message becomes "access denied".
func Forbidden(c *gin.Context, message string) {
	Error(c, apperror.Forbidden(message))
}

// InternalError writes a 500 response with message.
func InternalError(c *gin.Context, message string) {
	Error(c, apperror.Internal(message, nil))
}

// TooManyRequests writes a 429 response and a Retry-After header of retryAfter seconds (at least one).
func TooManyRequests(c *gin.Context, message string, retryAfter int) {
	retryAfter = max(1, retryAfter)
	c.Header("Retry-After", strconv.Itoa(retryAfter))
	Error(c, apperror.TooManyRequests(message, retryAfter))
}

// ValidationError writes a 400 response with the validation details.
func ValidationError(c *gin.Context, message string, details map[string]any) {
	Error(c, apperror.ValidationError(message, details))
}

// NewMeta builds pagination metadata; TotalPages is zero when pageSize is not positive.
func NewMeta(page, pageSize int, total int64) *Meta {
	totalPages := 0
	if pageSize > 0 {
		totalPages = int((total + int64(pageSize) - 1) / int64(pageSize))
	}
	return &Meta{Page: page, PageSize: pageSize, Total: total, TotalPages: totalPages}
}
