// Package middleware provides HTTP middleware components for the Gin framework.
// Пакет middleware предоставляет компоненты HTTP middleware для фреймворка Gin.
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// SecurityConfig holds security middleware configuration.
// SecurityConfig содержит конфигурацию middleware безопасности.
type SecurityConfig struct {
	// CORS settings / Настройки CORS
	AllowOrigins     []string // Allowed origins / Разрешённые источники
	AllowMethods     []string // Allowed HTTP methods / Разрешённые HTTP методы
	AllowHeaders     []string // Allowed request headers / Разрешённые заголовки запроса
	ExposeHeaders    []string // Headers exposed to client / Заголовки, доступные клиенту
	AllowCredentials bool     // Allow credentials / Разрешить учётные данные
	MaxAge           int      // Preflight cache duration (seconds) / Длительность кэша preflight (секунды)

	// Security headers / Заголовки безопасности
	ContentSecurityPolicy   string // CSP header value / Значение заголовка CSP
	XFrameOptions           string // X-Frame-Options header / Заголовок X-Frame-Options
	XContentTypeOptions     string // X-Content-Type-Options header / Заголовок X-Content-Type-Options
	XXSSProtection          string // X-XSS-Protection header / Заголовок X-XSS-Protection
	ReferrerPolicy          string // Referrer-Policy header / Заголовок Referrer-Policy
	StrictTransportSecurity string // HSTS header / Заголовок HSTS
}

// DefaultSecurityConfig returns default security configuration.
// DefaultSecurityConfig возвращает конфигурацию безопасности по умолчанию.
// Suitable for development. Use ProductionSecurityConfig for production.
// Подходит для разработки. Для продакшена используйте ProductionSecurityConfig.
func DefaultSecurityConfig() SecurityConfig {
	return SecurityConfig{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Limit", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           86400, // 24 hours / 24 часа

		ContentSecurityPolicy:   "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'",
		XFrameOptions:           "DENY",
		XContentTypeOptions:     "nosniff",
		XXSSProtection:          "1; mode=block",
		ReferrerPolicy:          "strict-origin-when-cross-origin",
		StrictTransportSecurity: "max-age=31536000; includeSubDomains",
	}
}

// ProductionSecurityConfig returns stricter security configuration for production.
// ProductionSecurityConfig возвращает более строгую конфигурацию безопасности для продакшена.
func ProductionSecurityConfig(allowedOrigins []string) SecurityConfig {
	cfg := DefaultSecurityConfig()
	cfg.AllowOrigins = allowedOrigins
	cfg.ContentSecurityPolicy = "default-src 'none'"
	return cfg
}

// SecurityHeaders returns a middleware that adds security headers to responses.
// SecurityHeaders возвращает middleware, который добавляет заголовки безопасности к ответам.
//
// Headers added / Добавляемые заголовки:
//   - X-Content-Type-Options: prevents MIME type sniffing / предотвращает MIME sniffing
//   - X-Frame-Options: prevents clickjacking / предотвращает clickjacking
//   - X-XSS-Protection: enables XSS filter / включает XSS фильтр
//   - Referrer-Policy: controls referrer information / контролирует информацию о referrer
//   - Content-Security-Policy: restricts resource loading / ограничивает загрузку ресурсов
//   - Strict-Transport-Security: enforces HTTPS / принуждает использовать HTTPS
func SecurityHeaders(config SecurityConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Set security headers / Устанавливаем заголовки безопасности
		c.Header("X-Content-Type-Options", config.XContentTypeOptions)
		c.Header("X-Frame-Options", config.XFrameOptions)
		c.Header("X-XSS-Protection", config.XXSSProtection)
		c.Header("Referrer-Policy", config.ReferrerPolicy)

		// Only set CSP for non-Swagger paths (Swagger needs inline scripts)
		// CSP только для не-Swagger путей (Swagger требует inline скриптов)
		if !strings.HasPrefix(c.Request.URL.Path, "/swagger") {
			c.Header("Content-Security-Policy", config.ContentSecurityPolicy)
		}

		// HSTS only for HTTPS connections / HSTS только для HTTPS соединений
		if c.Request.TLS != nil || c.GetHeader("X-Forwarded-Proto") == "https" {
			c.Header("Strict-Transport-Security", config.StrictTransportSecurity)
		}

		c.Next()
	}
}

// CORS returns a middleware that handles Cross-Origin Resource Sharing.
// CORS возвращает middleware, который обрабатывает Cross-Origin Resource Sharing.
//
// Handles preflight OPTIONS requests and sets appropriate CORS headers.
// Обрабатывает preflight OPTIONS запросы и устанавливает соответствующие CORS заголовки.
func CORS(config SecurityConfig) gin.HandlerFunc {
	allowAllOrigins := len(config.AllowOrigins) == 1 && config.AllowOrigins[0] == "*"

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")

		// Handle preflight requests / Обрабатываем preflight запросы
		if c.Request.Method == http.MethodOptions {
			switch {
			case allowAllOrigins:
				c.Header("Access-Control-Allow-Origin", "*")
			case isOriginAllowed(origin, config.AllowOrigins):
				c.Header("Access-Control-Allow-Origin", origin)
			default:
				c.AbortWithStatus(http.StatusForbidden)
				return
			}

			c.Header("Access-Control-Allow-Methods", strings.Join(config.AllowMethods, ", "))
			c.Header("Access-Control-Allow-Headers", strings.Join(config.AllowHeaders, ", "))
			c.Header("Access-Control-Max-Age", string(rune(config.MaxAge)))

			// Don't allow credentials with wildcard origin
			// Не разрешаем credentials с wildcard origin
			if config.AllowCredentials && !allowAllOrigins {
				c.Header("Access-Control-Allow-Credentials", "true")
			}

			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		// Handle actual requests / Обрабатываем обычные запросы
		switch {
		case allowAllOrigins:
			c.Header("Access-Control-Allow-Origin", "*")
		case isOriginAllowed(origin, config.AllowOrigins):
			c.Header("Access-Control-Allow-Origin", origin)
			if config.AllowCredentials {
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		}

		// Expose headers to client / Делаем заголовки доступными клиенту
		if len(config.ExposeHeaders) > 0 {
			c.Header("Access-Control-Expose-Headers", strings.Join(config.ExposeHeaders, ", "))
		}

		c.Next()
	}
}

// isOriginAllowed checks if the origin is in the allowed list.
// isOriginAllowed проверяет, находится ли origin в списке разрешённых.
func isOriginAllowed(origin string, allowed []string) bool {
	for _, a := range allowed {
		if a == origin || a == "*" {
			return true
		}
	}
	return false
}

// NoCache returns a middleware that adds cache-control headers to prevent caching.
// NoCache возвращает middleware, который добавляет заголовки для предотвращения кэширования.
// Use this for sensitive endpoints like authentication.
// Используйте для чувствительных эндпоинтов, например, аутентификации.
func NoCache() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate")
		c.Header("Pragma", "no-cache")
		c.Header("Expires", "0")
		c.Next()
	}
}
