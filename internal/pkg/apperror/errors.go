// Package apperror provides structured application error types.
// Пакет apperror предоставляет структурированные типы ошибок приложения.
//
// This package implements a consistent error handling pattern with:
// - Error codes for programmatic handling
// - Human-readable messages
// - HTTP status code mapping
// - Optional details and wrapped errors
//
// Этот пакет реализует согласованный паттерн обработки ошибок с:
// - Кодами ошибок для программной обработки
// - Человекочитаемыми сообщениями
// - Сопоставлением HTTP статус-кодов
// - Опциональными деталями и обёрнутыми ошибками
package apperror

import (
	"errors"
	"fmt"
	"net/http"
)

// Error codes for different error types.
// Коды ошибок для различных типов ошибок.
const (
	CodeNotFound           = "NOT_FOUND"           // Resource not found / Ресурс не найден
	CodeValidation         = "VALIDATION_ERROR"    // Validation failed / Ошибка валидации
	CodeUnauthorized       = "UNAUTHORIZED"        // Authentication required / Требуется аутентификация
	CodeForbidden          = "FORBIDDEN"           // Access denied / Доступ запрещён
	CodeConflict           = "CONFLICT"            // Resource conflict / Конфликт ресурсов
	CodeInternal           = "INTERNAL_ERROR"      // Internal server error / Внутренняя ошибка сервера
	CodeBadRequest         = "BAD_REQUEST"         // Invalid request / Неверный запрос
	CodeTooManyRequests    = "TOO_MANY_REQUESTS"   // Rate limit exceeded / Превышен лимит запросов
	CodeServiceUnavailable = "SERVICE_UNAVAILABLE" // Service unavailable / Сервис недоступен
	CodePasswordExpired    = "PASSWORD_EXPIRED"    // Password has expired / Пароль истёк
)

// AppError represents a structured application error.
// AppError представляет структурированную ошибку приложения.
//
// Fields / Поля:
//   - Code: Machine-readable error code / Машиночитаемый код ошибки
//   - Message: Human-readable error message / Человекочитаемое сообщение
//   - HTTPStatus: Corresponding HTTP status code / Соответствующий HTTP статус-код
//   - Details: Additional error details / Дополнительные детали ошибки
//   - Err: Wrapped underlying error / Обёрнутая исходная ошибка
type AppError struct {
	Code       string                 `json:"code"`              // Error code / Код ошибки
	Message    string                 `json:"message"`           // Error message / Сообщение об ошибке
	HTTPStatus int                    `json:"-"`                 // HTTP status / HTTP статус
	Details    map[string]interface{} `json:"details,omitempty"` // Additional details / Доп. детали
	Err        error                  `json:"-"`                 // Wrapped error / Обёрнутая ошибка
}

// Error implements the error interface.
// Error реализует интерфейс error.
func (e *AppError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %s: %v", e.Code, e.Message, e.Err)
	}
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// Unwrap returns the wrapped error for errors.Is/As support.
// Unwrap возвращает обёрнутую ошибку для поддержки errors.Is/As.
func (e *AppError) Unwrap() error {
	return e.Err
}

// WithDetails adds details to the error and returns the modified error.
// WithDetails добавляет детали к ошибке и возвращает изменённую ошибку.
func (e *AppError) WithDetails(details map[string]interface{}) *AppError {
	e.Details = details
	return e
}

// WithError wraps an underlying error and returns the modified error.
// WithError оборачивает исходную ошибку и возвращает изменённую ошибку.
func (e *AppError) WithError(err error) *AppError {
	e.Err = err
	return e
}

// New creates a new AppError with the specified code, message, and HTTP status.
// New создаёт новую AppError с указанным кодом, сообщением и HTTP статусом.
func New(code, message string, httpStatus int) *AppError {
	return &AppError{
		Code:       code,
		Message:    message,
		HTTPStatus: httpStatus,
	}
}

// NotFound creates a not found error for a specific resource.
// NotFound создаёт ошибку "не найдено" для конкретного ресурса.
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
// ValidationError создаёт ошибку валидации с деталями.
func ValidationError(message string, details map[string]interface{}) *AppError {
	return &AppError{
		Code:       CodeValidation,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
		Details:    details,
	}
}

// Unauthorized creates an authentication error.
// Unauthorized создаёт ошибку аутентификации.
func Unauthorized(message string) *AppError {
	if message == "" {
		message = "authentication required" // Требуется аутентификация
	}
	return &AppError{
		Code:       CodeUnauthorized,
		Message:    message,
		HTTPStatus: http.StatusUnauthorized,
	}
}

// Forbidden creates an authorization/access denied error.
// Forbidden создаёт ошибку авторизации/отказа в доступе.
func Forbidden(message string) *AppError {
	if message == "" {
		message = "access denied" // Доступ запрещён
	}
	return &AppError{
		Code:       CodeForbidden,
		Message:    message,
		HTTPStatus: http.StatusForbidden,
	}
}

// Conflict creates a resource conflict error (e.g., duplicate entry).
// Conflict создаёт ошибку конфликта ресурсов (например, дубликат записи).
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
// Internal создаёт внутреннюю ошибку сервера с опциональной обёрнутой ошибкой.
func Internal(message string, err error) *AppError {
	return &AppError{
		Code:       CodeInternal,
		Message:    message,
		HTTPStatus: http.StatusInternalServerError,
		Err:        err,
	}
}

// BadRequest creates a bad request error.
// BadRequest создаёт ошибку неверного запроса.
func BadRequest(message string) *AppError {
	return &AppError{
		Code:       CodeBadRequest,
		Message:    message,
		HTTPStatus: http.StatusBadRequest,
	}
}

// TooManyRequests creates a rate limit exceeded error.
// TooManyRequests создаёт ошибку превышения лимита запросов.
func TooManyRequests(message string, retryAfter int) *AppError {
	return &AppError{
		Code:       CodeTooManyRequests,
		Message:    message,
		HTTPStatus: http.StatusTooManyRequests,
		Details: map[string]interface{}{
			"retry_after_seconds": retryAfter, // Retry after X seconds / Повторите через X секунд
		},
	}
}

// ServiceUnavailable creates a service unavailable error.
// ServiceUnavailable создаёт ошибку недоступности сервиса.
func ServiceUnavailable(message string) *AppError {
	return &AppError{
		Code:       CodeServiceUnavailable,
		Message:    message,
		HTTPStatus: http.StatusServiceUnavailable,
	}
}

// PasswordExpired creates a password expired error.
// PasswordExpired создаёт ошибку истёкшего пароля.
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
// IsAppError проверяет, является ли ошибка AppError.
func IsAppError(err error) bool {
	var appErr *AppError
	return errors.As(err, &appErr)
}

// AsAppError converts an error to AppError if possible.
// AsAppError преобразует ошибку в AppError, если это возможно.
// Returns the AppError and true if successful, nil and false otherwise.
// Возвращает AppError и true при успехе, nil и false в противном случае.
func AsAppError(err error) (*AppError, bool) {
	var appErr *AppError
	if errors.As(err, &appErr) {
		return appErr, true
	}
	return nil, false
}

// FromError wraps a generic error as an internal AppError.
// FromError оборачивает обычную ошибку как внутреннюю AppError.
// If the error is already an AppError, it returns it as-is.
// Если ошибка уже является AppError, возвращает её без изменений.
func FromError(err error) *AppError {
	if err == nil {
		return nil
	}
	if appErr, ok := AsAppError(err); ok {
		return appErr
	}
	return Internal("an unexpected error occurred", err) // Произошла непредвиденная ошибка
}
