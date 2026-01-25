// Package middleware provides HTTP middleware components for the Gin framework.
// Пакет middleware предоставляет компоненты HTTP middleware для фреймворка Gin.
package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Constants for request ID handling.
// Константы для обработки ID запроса.
const (
	// RequestIDHeader is the HTTP header name for request ID.
	// RequestIDHeader — имя HTTP заголовка для ID запроса.
	RequestIDHeader = "X-Request-ID"

	// RequestIDKey is the context key for storing request ID.
	// RequestIDKey — ключ контекста для хранения ID запроса.
	RequestIDKey = "request_id"
)

// RequestID returns a middleware that generates and sets a unique request ID.
// RequestID возвращает middleware, который генерирует и устанавливает уникальный ID запроса.
//
// If the client provides X-Request-ID header, it will be used.
// Otherwise, a new UUID will be generated.
// Если клиент предоставляет заголовок X-Request-ID, он будет использован.
// В противном случае будет сгенерирован новый UUID.
func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Check if request ID is already provided by client
		// Проверяем, предоставил ли клиент ID запроса
		requestID := c.GetHeader(RequestIDHeader)
		if requestID == "" {
			requestID = uuid.New().String()
		}

		// Set request ID in Gin context / Устанавливаем ID запроса в контекст Gin
		c.Set(RequestIDKey, requestID)

		// Add request ID to logger context for distributed tracing
		// Добавляем ID запроса в контекст логгера для распределённой трассировки
		ctx := logger.WithRequestIDContext(c.Request.Context(), requestID)
		c.Request = c.Request.WithContext(ctx)

		// Set request ID in response header / Устанавливаем ID запроса в заголовок ответа
		c.Header(RequestIDHeader, requestID)

		c.Next()
	}
}

// GetRequestID retrieves the request ID from Gin context.
// GetRequestID получает ID запроса из контекста Gin.
// Returns empty string if request ID is not set.
// Возвращает пустую строку, если ID запроса не установлен.
func GetRequestID(c *gin.Context) string {
	if id, exists := c.Get(RequestIDKey); exists {
		if strID, ok := id.(string); ok {
			return strID
		}
	}
	return ""
}
