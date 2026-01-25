// Package middleware provides HTTP middleware components for the Gin framework.
// Пакет middleware предоставляет компоненты HTTP middleware для фреймворка Gin.
package middleware

import (
	"fmt"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// RateLimitConfig holds rate limiter configuration.
// RateLimitConfig содержит конфигурацию ограничителя частоты запросов.
type RateLimitConfig struct {
	// RequestsPerSecond is the global rate limit per IP.
	// RequestsPerSecond — глобальный лимит запросов в секунду на IP.
	RequestsPerSecond float64

	// Burst is the maximum number of requests allowed in a burst.
	// Burst — максимальное количество запросов, разрешённых в пике.
	Burst int

	// LoginAttemptsPerMinute is the login rate limit per IP.
	// LoginAttemptsPerMinute — лимит попыток входа в минуту на IP.
	LoginAttemptsPerMinute int

	// LoginBurst is the maximum login attempts allowed in a burst.
	// LoginBurst — максимальное количество попыток входа в пике.
	LoginBurst int
}

// DefaultRateLimitConfig returns default rate limit configuration.
// DefaultRateLimitConfig возвращает конфигурацию ограничения частоты по умолчанию.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerSecond:      100, // 100 requests per second / 100 запросов в секунду
		Burst:                  200, // Allow burst of 200 / Разрешить пик до 200
		LoginAttemptsPerMinute: 5,   // 5 login attempts per minute / 5 попыток входа в минуту
		LoginBurst:             10,  // Allow burst of 10 / Разрешить пик до 10
	}
}

// IPRateLimiter is an in-memory rate limiter per IP address.
// IPRateLimiter — ограничитель частоты в памяти на IP-адрес.
//
// Suitable for single-instance deployments. For distributed systems,
// use RedisRateLimiter instead.
// Подходит для однокопийных развёртываний. Для распределённых систем
// используйте RedisRateLimiter.
type IPRateLimiter struct {
	limiters map[string]*rate.Limiter // IP -> Limiter mapping / Сопоставление IP -> Limiter
	config   RateLimitConfig          // Configuration / Конфигурация
}

// NewIPRateLimiter creates a new in-memory IP rate limiter.
// NewIPRateLimiter создаёт новый in-memory ограничитель частоты по IP.
func NewIPRateLimiter(config RateLimitConfig) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// GetLimiter returns the rate limiter for the given IP address.
// GetLimiter возвращает ограничитель частоты для данного IP-адреса.
// Creates a new limiter if one doesn't exist.
// Создаёт новый ограничитель, если он не существует.
func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(l.config.RequestsPerSecond), l.config.Burst)
		l.limiters[ip] = limiter
	}
	return limiter
}

// GetLoginLimiter returns the login rate limiter for the given IP address.
// GetLoginLimiter возвращает ограничитель частоты входа для данного IP-адреса.
func (l *IPRateLimiter) GetLoginLimiter(ip string) *rate.Limiter {
	key := "login:" + ip
	limiter, exists := l.limiters[key]
	if !exists {
		// Convert per minute to per second / Конвертируем из "в минуту" в "в секунду"
		rps := float64(l.config.LoginAttemptsPerMinute) / 60.0
		limiter = rate.NewLimiter(rate.Limit(rps), l.config.LoginBurst)
		l.limiters[key] = limiter
	}
	return limiter
}

// RateLimitMiddleware returns a Gin middleware for global rate limiting.
// RateLimitMiddleware возвращает Gin middleware для глобального ограничения частоты.
func RateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		l := limiter.GetLimiter(ip)

		if !l.Allow() {
			c.Header("Retry-After", "1")
			response.TooManyRequests(c, "rate limit exceeded", 1)
			c.Abort()
			return
		}

		c.Next()
	}
}

// LoginRateLimitMiddleware returns a Gin middleware for login rate limiting.
// LoginRateLimitMiddleware возвращает Gin middleware для ограничения частоты входа.
// More restrictive than global rate limiting to prevent brute-force attacks.
// Более строгий, чем глобальное ограничение, для предотвращения brute-force атак.
func LoginRateLimitMiddleware(limiter *IPRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		l := limiter.GetLoginLimiter(ip)

		if !l.Allow() {
			c.Header("Retry-After", "60")
			response.TooManyRequests(c, "too many login attempts, please try again later", 60)
			c.Abort()
			return
		}

		c.Next()
	}
}

// RedisRateLimiter uses Redis for distributed rate limiting.
// RedisRateLimiter использует Redis для распределённого ограничения частоты.
//
// Suitable for multi-instance deployments where rate limits must be
// shared across all instances.
// Подходит для многокопийных развёртываний, где лимиты частоты
// должны разделяться между всеми экземплярами.
type RedisRateLimiter struct {
	cache  port.RateLimitCache // Redis cache interface / Интерфейс Redis кэша
	config RateLimitConfig     // Configuration / Конфигурация
}

// NewRedisRateLimiter creates a new Redis-based rate limiter.
// NewRedisRateLimiter создаёт новый ограничитель частоты на базе Redis.
func NewRedisRateLimiter(cache port.RateLimitCache, config RateLimitConfig) *RedisRateLimiter {
	return &RedisRateLimiter{
		cache:  cache,
		config: config,
	}
}

// RedisRateLimitMiddleware returns a Gin middleware for Redis-based global rate limiting.
// RedisRateLimitMiddleware возвращает Gin middleware для глобального ограничения частоты на базе Redis.
func RedisRateLimitMiddleware(limiter *RedisRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("global:%s", ip)
		window := time.Second

		count, err := limiter.cache.Increment(c.Request.Context(), key, window)
		if err != nil {
			// On error, allow the request but log it
			// При ошибке разрешаем запрос, но логируем
			c.Next()
			return
		}

		if count > int64(limiter.config.Burst) {
			c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.config.Burst))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("Retry-After", "1")
			response.TooManyRequests(c, "rate limit exceeded", 1)
			c.Abort()
			return
		}

		// Set rate limit headers / Устанавливаем заголовки лимита частоты
		remaining := int64(limiter.config.Burst) - count
		if remaining < 0 {
			remaining = 0
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(limiter.config.Burst))
		c.Header("X-RateLimit-Remaining", strconv.FormatInt(remaining, 10))

		c.Next()
	}
}

// RedisLoginRateLimitMiddleware returns a Gin middleware for Redis-based login rate limiting.
// RedisLoginRateLimitMiddleware возвращает Gin middleware для ограничения частоты входа на базе Redis.
func RedisLoginRateLimitMiddleware(limiter *RedisRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("login:%s", ip)
		window := time.Minute

		count, err := limiter.cache.Increment(c.Request.Context(), key, window)
		if err != nil {
			// On error, allow the request but log it
			// При ошибке разрешаем запрос, но логируем
			c.Next()
			return
		}

		if count > int64(limiter.config.LoginAttemptsPerMinute) {
			c.Header("Retry-After", "60")
			response.TooManyRequests(c, "too many login attempts, please try again later", 60)
			c.Abort()
			return
		}

		c.Next()
	}
}
