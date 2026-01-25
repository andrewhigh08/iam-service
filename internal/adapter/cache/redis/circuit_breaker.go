// Package redis provides Redis-based cache implementations with circuit breaker protection.
// Пакет redis предоставляет реализации кэша на базе Redis с защитой circuit breaker.
package redis

import (
	"context"
	"time"

	"github.com/andrewhigh08/iam-service/internal/pkg/circuitbreaker"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// CircuitBreakerConfig holds configuration for cache circuit breakers.
// CircuitBreakerConfig содержит конфигурацию circuit breaker для кэша.
type CircuitBreakerConfig struct {
	// MaxFailures is the number of failures before opening the circuit.
	// MaxFailures - количество сбоев до размыкания цепи.
	MaxFailures int

	// Timeout is the duration to wait before testing if service recovered.
	// Timeout - время ожидания перед проверкой восстановления сервиса.
	Timeout time.Duration

	// OnStateChange is called when circuit breaker state changes.
	// OnStateChange вызывается при изменении состояния circuit breaker.
	OnStateChange func(name string, from, to circuitbreaker.State)
}

// DefaultCircuitBreakerConfig returns default circuit breaker configuration for Redis.
// DefaultCircuitBreakerConfig возвращает конфигурацию circuit breaker по умолчанию для Redis.
func DefaultCircuitBreakerConfig() CircuitBreakerConfig {
	return CircuitBreakerConfig{
		MaxFailures: 5,
		Timeout:     30 * time.Second,
	}
}

// ==================== Authorization Cache with Circuit Breaker ====================

// AuthorizationCacheWithCB wraps AuthorizationCache with circuit breaker protection.
// AuthorizationCacheWithCB оборачивает AuthorizationCache с защитой circuit breaker.
type AuthorizationCacheWithCB struct {
	cache *AuthorizationCache
	cb    *circuitbreaker.CircuitBreaker
}

// NewAuthorizationCacheWithCB creates a new AuthorizationCache with circuit breaker.
// NewAuthorizationCacheWithCB создаёт новый AuthorizationCache с circuit breaker.
func NewAuthorizationCacheWithCB(cache *AuthorizationCache, config CircuitBreakerConfig) *AuthorizationCacheWithCB {
	cbConfig := circuitbreaker.Config{
		Name:                "redis-authz-cache",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &AuthorizationCacheWithCB{
		cache: cache,
		cb:    circuitbreaker.New(cbConfig),
	}
}

// GetDecision retrieves a cached authorization decision with circuit breaker protection.
// GetDecision получает закэшированное решение авторизации с защитой circuit breaker.
func (c *AuthorizationCacheWithCB) GetDecision(ctx context.Context, userID int64, resource, action string) (allowed, found bool, err error) {
	type result struct {
		allowed bool
		found   bool
	}

	r, cbErr := circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (result, error) {
		a, f, e := c.cache.GetDecision(ctx, userID, resource, action)
		return result{allowed: a, found: f}, e
	})

	if cbErr != nil {
		// On circuit breaker open, return cache miss (graceful degradation).
		// При открытом circuit breaker возвращаем cache miss (graceful degradation).
		return false, false, nil //nolint:nilerr // intentional: graceful degradation on CB open
	}

	return r.allowed, r.found, nil
}

// SetDecision caches an authorization decision with circuit breaker protection.
// SetDecision кэширует решение авторизации с защитой circuit breaker.
func (c *AuthorizationCacheWithCB) SetDecision(ctx context.Context, userID int64, resource, action string, allowed bool, expiration time.Duration) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.SetDecision(ctx, userID, resource, action, allowed, expiration)
	})
}

// InvalidateUser invalidates all cached decisions for a user with circuit breaker protection.
// InvalidateUser инвалидирует все решения для пользователя с защитой circuit breaker.
func (c *AuthorizationCacheWithCB) InvalidateUser(ctx context.Context, userID int64) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.InvalidateUser(ctx, userID)
	})
}

// InvalidateAll invalidates all cached decisions with circuit breaker protection.
// InvalidateAll инвалидирует все решения с защитой circuit breaker.
func (c *AuthorizationCacheWithCB) InvalidateAll(ctx context.Context) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.InvalidateAll(ctx)
	})
}

// CircuitBreakerState returns the current state of the circuit breaker.
// CircuitBreakerState возвращает текущее состояние circuit breaker.
func (c *AuthorizationCacheWithCB) CircuitBreakerState() circuitbreaker.State {
	return c.cb.State()
}

// Ensure interface compliance. / Проверка соответствия интерфейсу.
var _ port.AuthorizationCache = (*AuthorizationCacheWithCB)(nil)

// ==================== Rate Limit Cache with Circuit Breaker ====================

// RateLimitCacheWithCB wraps RateLimitCache with circuit breaker protection.
// RateLimitCacheWithCB оборачивает RateLimitCache с защитой circuit breaker.
type RateLimitCacheWithCB struct {
	cache *RateLimitCache
	cb    *circuitbreaker.CircuitBreaker
}

// NewRateLimitCacheWithCB creates a new RateLimitCache with circuit breaker.
// NewRateLimitCacheWithCB создаёт новый RateLimitCache с circuit breaker.
func NewRateLimitCacheWithCB(cache *RateLimitCache, config CircuitBreakerConfig) *RateLimitCacheWithCB {
	cbConfig := circuitbreaker.Config{
		Name:                "redis-ratelimit-cache",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &RateLimitCacheWithCB{
		cache: cache,
		cb:    circuitbreaker.New(cbConfig),
	}
}

// Increment increments a rate limit counter with circuit breaker protection.
// Increment увеличивает счётчик rate limit с защитой circuit breaker.
func (c *RateLimitCacheWithCB) Increment(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	return circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (int64, error) {
		return c.cache.Increment(ctx, key, expiration)
	})
}

// GetCount retrieves current count with circuit breaker protection.
// GetCount получает текущий счётчик с защитой circuit breaker.
func (c *RateLimitCacheWithCB) GetCount(ctx context.Context, key string) (int64, error) {
	return circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (int64, error) {
		return c.cache.GetCount(ctx, key)
	})
}

// Reset resets a rate limit counter with circuit breaker protection.
// Reset сбрасывает счётчик rate limit с защитой circuit breaker.
func (c *RateLimitCacheWithCB) Reset(ctx context.Context, key string) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.Reset(ctx, key)
	})
}

// CircuitBreakerState returns the current state of the circuit breaker.
// CircuitBreakerState возвращает текущее состояние circuit breaker.
func (c *RateLimitCacheWithCB) CircuitBreakerState() circuitbreaker.State {
	return c.cb.State()
}

// Ensure interface compliance. / Проверка соответствия интерфейсу.
var _ port.RateLimitCache = (*RateLimitCacheWithCB)(nil)

// ==================== Token Cache with Circuit Breaker ====================

// TokenCacheWithCB wraps TokenCache with circuit breaker protection.
// TokenCacheWithCB оборачивает TokenCache с защитой circuit breaker.
type TokenCacheWithCB struct {
	cache *TokenCache
	cb    *circuitbreaker.CircuitBreaker
}

// NewTokenCacheWithCB creates a new TokenCache with circuit breaker.
// NewTokenCacheWithCB создаёт новый TokenCache с circuit breaker.
func NewTokenCacheWithCB(cache *TokenCache, config CircuitBreakerConfig) *TokenCacheWithCB {
	cbConfig := circuitbreaker.Config{
		Name:                "redis-token-cache",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &TokenCacheWithCB{
		cache: cache,
		cb:    circuitbreaker.New(cbConfig),
	}
}

// BlacklistToken adds a token to blacklist with circuit breaker protection.
// BlacklistToken добавляет токен в чёрный список с защитой circuit breaker.
func (c *TokenCacheWithCB) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.BlacklistToken(ctx, tokenID, expiration)
	})
}

// IsBlacklisted checks if token is blacklisted with circuit breaker protection.
// IsBlacklisted проверяет, заблокирован ли токен, с защитой circuit breaker.
func (c *TokenCacheWithCB) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	result, cbErr := circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (bool, error) {
		return c.cache.IsBlacklisted(ctx, tokenID)
	})

	if cbErr != nil {
		// On circuit breaker open, assume token is not blacklisted (fail open for availability).
		// При открытом circuit breaker считаем токен не заблокированным (fail open для доступности).
		// Note: This is a security trade-off. In high-security scenarios, consider fail closed.
		// Примечание: Это компромисс безопасности. В высокобезопасных сценариях рассмотрите fail closed.
		return false, nil //nolint:nilerr // intentional: fail open for availability
	}

	return result, nil
}

// CircuitBreakerState returns the current state of the circuit breaker.
// CircuitBreakerState возвращает текущее состояние circuit breaker.
func (c *TokenCacheWithCB) CircuitBreakerState() circuitbreaker.State {
	return c.cb.State()
}

// Ensure interface compliance. / Проверка соответствия интерфейсу.
var _ port.TokenCache = (*TokenCacheWithCB)(nil)

// ==================== Refresh Token Cache with Circuit Breaker ====================

// RefreshTokenCacheWithCB wraps RefreshTokenCache with circuit breaker protection.
// RefreshTokenCacheWithCB оборачивает RefreshTokenCache с защитой circuit breaker.
type RefreshTokenCacheWithCB struct {
	cache *RefreshTokenCache
	cb    *circuitbreaker.CircuitBreaker
}

// NewRefreshTokenCacheWithCB creates a new RefreshTokenCache with circuit breaker.
// NewRefreshTokenCacheWithCB создаёт новый RefreshTokenCache с circuit breaker.
func NewRefreshTokenCacheWithCB(cache *RefreshTokenCache, config CircuitBreakerConfig) *RefreshTokenCacheWithCB {
	cbConfig := circuitbreaker.Config{
		Name:                "redis-refresh-token-cache",
		MaxFailures:         config.MaxFailures,
		Timeout:             config.Timeout,
		MaxHalfOpenRequests: 1,
		OnStateChange:       config.OnStateChange,
	}
	return &RefreshTokenCacheWithCB{
		cache: cache,
		cb:    circuitbreaker.New(cbConfig),
	}
}

// StoreRefreshToken stores a refresh token with circuit breaker protection.
// StoreRefreshToken сохраняет refresh токен с защитой circuit breaker.
func (c *RefreshTokenCacheWithCB) StoreRefreshToken(ctx context.Context, tokenID string, userID int64, expiration time.Duration) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.StoreRefreshToken(ctx, tokenID, userID, expiration)
	})
}

// GetRefreshToken retrieves user ID for a refresh token with circuit breaker protection.
// GetRefreshToken получает ID пользователя для refresh токена с защитой circuit breaker.
func (c *RefreshTokenCacheWithCB) GetRefreshToken(ctx context.Context, tokenID string) (int64, error) {
	return circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (int64, error) {
		return c.cache.GetRefreshToken(ctx, tokenID)
	})
}

// DeleteRefreshToken removes a refresh token with circuit breaker protection.
// DeleteRefreshToken удаляет refresh токен с защитой circuit breaker.
func (c *RefreshTokenCacheWithCB) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.DeleteRefreshToken(ctx, tokenID)
	})
}

// DeleteUserRefreshTokens removes all user's refresh tokens with circuit breaker protection.
// DeleteUserRefreshTokens удаляет все refresh токены пользователя с защитой circuit breaker.
func (c *RefreshTokenCacheWithCB) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	return c.cb.Execute(ctx, func(ctx context.Context) error {
		return c.cache.DeleteUserRefreshTokens(ctx, userID)
	})
}

// GetUserTokens retrieves all user's tokens with circuit breaker protection.
// GetUserTokens получает все токены пользователя с защитой circuit breaker.
func (c *RefreshTokenCacheWithCB) GetUserTokens(ctx context.Context, userID int64) (map[string]int64, error) {
	return circuitbreaker.ExecuteWithResult(ctx, c.cb, func(ctx context.Context) (map[string]int64, error) {
		return c.cache.GetUserTokens(ctx, userID)
	})
}

// CircuitBreakerState returns the current state of the circuit breaker.
// CircuitBreakerState возвращает текущее состояние circuit breaker.
func (c *RefreshTokenCacheWithCB) CircuitBreakerState() circuitbreaker.State {
	return c.cb.State()
}

// Ensure interface compliance. / Проверка соответствия интерфейсу.
var _ port.RefreshTokenCache = (*RefreshTokenCacheWithCB)(nil)
