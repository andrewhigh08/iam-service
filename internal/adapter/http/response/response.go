// Package response provides standardized API response structures and helpers.
// Пакет response предоставляет стандартизированные структуры ответов API и вспомогательные функции.
//
// All API endpoints should use these helpers to ensure consistent response format.
// Все эндпоинты API должны использовать эти хелперы для обеспечения единообразного формата ответов.
package response

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// APIResponse represents a standardized API response structure.
// APIResponse представляет стандартизированную структуру ответа API.
//
// All API responses follow this format for consistency.
// Все ответы API следуют этому формату для единообразия.
type APIResponse struct {
	Success bool        `json:"success"`         // Operation success flag / Флаг успешности операции
	Data    interface{} `json:"data,omitempty"`  // Response payload / Полезные данные ответа
	Error   *ErrorBody  `json:"error,omitempty"` // Error details (if any) / Детали ошибки (если есть)
	Meta    *Meta       `json:"meta,omitempty"`  // Pagination metadata / Метаданные пагинации
}

// ErrorBody represents the error details in an API response.
// ErrorBody представляет детали ошибки в ответе API.
type ErrorBody struct {
	Code    string                 `json:"code"`              // Machine-readable error code / Машиночитаемый код ошибки
	Message string                 `json:"message"`           // Human-readable error message / Человекочитаемое сообщение
	Details map[string]interface{} `json:"details,omitempty"` // Additional error details / Дополнительные детали
}

// Meta represents pagination metadata in API responses.
// Meta представляет метаданные пагинации в ответах API.
type Meta struct {
	Page       int   `json:"page"`        // Current page number / Номер текущей страницы
	PageSize   int   `json:"page_size"`   // Items per page / Элементов на странице
	Total      int64 `json:"total"`       // Total items count / Общее количество элементов
	TotalPages int   `json:"total_pages"` // Total pages count / Общее количество страниц
}

// Success sends a successful response with data.
// Success отправляет успешный ответ с данными.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
	})
}

// SuccessWithMeta sends a successful response with data and pagination metadata.
// SuccessWithMeta отправляет успешный ответ с данными и метаданными пагинации.
func SuccessWithMeta(c *gin.Context, data interface{}, meta *Meta) {
	c.JSON(http.StatusOK, APIResponse{
		Success: true,
		Data:    data,
		Meta:    meta,
	})
}

// Created sends a successful response for resource creation (HTTP 201).
// Created отправляет успешный ответ при создании ресурса (HTTP 201).
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, APIResponse{
		Success: true,
		Data:    data,
	})
}

// NoContent sends a successful response with no content (HTTP 204).
// NoContent отправляет успешный ответ без содержимого (HTTP 204).
func NoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// Error sends an error response from an AppError.
// Error отправляет ответ с ошибкой из AppError.
// Automatically determines HTTP status code based on error type.
// Автоматически определяет HTTP статус-код на основе типа ошибки.
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
// ErrorWithStatus отправляет ответ с ошибкой с определённым HTTP статусом.
func ErrorWithStatus(c *gin.Context, status int, code, message string, details map[string]interface{}) {
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
// BadRequest отправляет ответ 400 Bad Request.
func BadRequest(c *gin.Context, message string) {
	Error(c, apperror.BadRequest(message))
}

// Unauthorized sends a 401 Unauthorized response.
// Unauthorized отправляет ответ 401 Unauthorized.
func Unauthorized(c *gin.Context, message string) {
	if message == "" {
		message = "authentication required" // Требуется аутентификация
	}
	Error(c, apperror.Unauthorized(message))
}

// Forbidden sends a 403 Forbidden response.
// Forbidden отправляет ответ 403 Forbidden.
func Forbidden(c *gin.Context, message string) {
	if message == "" {
		message = "access denied" // Доступ запрещён
	}
	Error(c, apperror.Forbidden(message))
}

// NotFound sends a 404 Not Found response.
// NotFound отправляет ответ 404 Not Found.
func NotFound(c *gin.Context, resource string, id interface{}) {
	Error(c, apperror.NotFound(resource, id))
}

// Conflict sends a 409 Conflict response.
// Conflict отправляет ответ 409 Conflict.
func Conflict(c *gin.Context, resource, field string, value interface{}) {
	Error(c, apperror.Conflict(resource, field, value))
}

// InternalError sends a 500 Internal Server Error response.
// InternalError отправляет ответ 500 Internal Server Error.
func InternalError(c *gin.Context, message string) {
	Error(c, apperror.Internal(message, nil))
}

// TooManyRequests sends a 429 Too Many Requests response.
// TooManyRequests отправляет ответ 429 Too Many Requests.
func TooManyRequests(c *gin.Context, message string, retryAfter int) {
	c.Header("Retry-After", string(rune(retryAfter)))
	Error(c, apperror.TooManyRequests(message, retryAfter))
}

// ValidationError sends a 400 response for validation errors.
// ValidationError отправляет ответ 400 для ошибок валидации.
func ValidationError(c *gin.Context, message string, details map[string]interface{}) {
	Error(c, apperror.ValidationError(message, details))
}

// NewMeta creates pagination metadata from given parameters.
// NewMeta создаёт метаданные пагинации из заданных параметров.
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
