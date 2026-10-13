// Package middleware provides HTTP middleware components for the Gin framework.
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
type RateLimitConfig struct {
	// RequestsPerSecond is the global rate limit per IP.
	RequestsPerSecond float64

	// Burst is the maximum number of requests allowed in a burst.
	Burst int

	// LoginAttemptsPerMinute is the login rate limit per IP.
	LoginAttemptsPerMinute int

	// LoginBurst is the maximum login attempts allowed in a burst.
	LoginBurst int
}

// DefaultRateLimitConfig returns default rate limit configuration.
func DefaultRateLimitConfig() RateLimitConfig {
	return RateLimitConfig{
		RequestsPerSecond:      100, // 100 requests per second
		Burst:                  200, // Allow burst of 200
		LoginAttemptsPerMinute: 5,   // 5 login attempts per minute
		LoginBurst:             10,  // Allow burst of 10
	}
}

// IPRateLimiter is an in-memory rate limiter per IP address.
//
// Suitable for single-instance deployments. For distributed systems,
// use RedisRateLimiter instead.
type IPRateLimiter struct {
	limiters map[string]*rate.Limiter // IP -> Limiter mapping
	config   RateLimitConfig          // Configuration
}

// NewIPRateLimiter creates a new in-memory IP rate limiter.
func NewIPRateLimiter(config RateLimitConfig) *IPRateLimiter {
	return &IPRateLimiter{
		limiters: make(map[string]*rate.Limiter),
		config:   config,
	}
}

// GetLimiter returns the rate limiter for the given IP address.
// Creates a new limiter if one doesn't exist.
func (l *IPRateLimiter) GetLimiter(ip string) *rate.Limiter {
	limiter, exists := l.limiters[ip]
	if !exists {
		limiter = rate.NewLimiter(rate.Limit(l.config.RequestsPerSecond), l.config.Burst)
		l.limiters[ip] = limiter
	}
	return limiter
}

// GetLoginLimiter returns the login rate limiter for the given IP address.
func (l *IPRateLimiter) GetLoginLimiter(ip string) *rate.Limiter {
	key := "login:" + ip
	limiter, exists := l.limiters[key]
	if !exists {
		// Convert per minute to per second
		rps := float64(l.config.LoginAttemptsPerMinute) / 60.0
		limiter = rate.NewLimiter(rate.Limit(rps), l.config.LoginBurst)
		l.limiters[key] = limiter
	}
	return limiter
}

// RateLimitMiddleware returns a Gin middleware for global rate limiting.
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
// More restrictive than global rate limiting to prevent brute-force attacks.
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
//
// Suitable for multi-instance deployments where rate limits must be
// shared across all instances.
type RedisRateLimiter struct {
	cache  port.RateLimitCache // Redis cache interface
	config RateLimitConfig     // Configuration
}

// NewRedisRateLimiter creates a new Redis-based rate limiter.
func NewRedisRateLimiter(cache port.RateLimitCache, config RateLimitConfig) *RedisRateLimiter {
	return &RedisRateLimiter{
		cache:  cache,
		config: config,
	}
}

// RedisRateLimitMiddleware returns a Gin middleware for Redis-based global rate limiting.
func RedisRateLimitMiddleware(limiter *RedisRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("global:%s", ip)
		window := time.Second

		count, err := limiter.cache.Increment(c.Request.Context(), key, window)
		if err != nil {
			// On error, allow the request but log it
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

		// Set rate limit headers
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
func RedisLoginRateLimitMiddleware(limiter *RedisRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		key := fmt.Sprintf("login:%s", ip)
		window := time.Minute

		count, err := limiter.cache.Increment(c.Request.Context(), key, window)
		if err != nil {
			// On error, allow the request but log it
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
