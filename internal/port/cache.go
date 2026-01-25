// Package port defines interfaces (ports) for the application's external dependencies.
// Пакет port определяет интерфейсы (порты) для внешних зависимостей приложения.
package port

import (
	"context"
	"time"
)

// Cache defines the interface for generic caching operations.
// Cache определяет интерфейс для базовых операций кэширования.
//
// This interface provides a simple key-value cache abstraction
// that can be implemented by Redis, Memcached, or in-memory stores.
// Этот интерфейс предоставляет простую абстракцию кэша "ключ-значение",
// которая может быть реализована Redis, Memcached или in-memory хранилищами.
type Cache interface {
	// Get retrieves a value from the cache by key.
	// Get получает значение из кэша по ключу.
	// Returns empty string and error if key doesn't exist.
	// Возвращает пустую строку и ошибку, если ключ не существует.
	Get(ctx context.Context, key string) (string, error)

	// Set stores a value in the cache with an expiration time.
	// Set сохраняет значение в кэше с временем истечения.
	Set(ctx context.Context, key string, value string, expiration time.Duration) error

	// Delete removes a value from the cache.
	// Delete удаляет значение из кэша.
	Delete(ctx context.Context, key string) error

	// DeleteByPattern removes all values matching a glob pattern.
	// DeleteByPattern удаляет все значения, соответствующие шаблону glob.
	// Example: "user:*" deletes all keys starting with "user:"
	// Пример: "user:*" удаляет все ключи, начинающиеся с "user:"
	DeleteByPattern(ctx context.Context, pattern string) error

	// Exists checks if a key exists in the cache.
	// Exists проверяет, существует ли ключ в кэше.
	Exists(ctx context.Context, key string) (bool, error)
}

// AuthorizationCache defines the interface for caching authorization decisions.
// AuthorizationCache определяет интерфейс для кэширования решений авторизации.
//
// Caching authorization decisions significantly improves performance
// by avoiding repeated database lookups for the same access checks.
// Кэширование решений авторизации значительно улучшает производительность,
// избегая повторных запросов к БД для одних и тех же проверок доступа.
type AuthorizationCache interface {
	// GetDecision retrieves a cached authorization decision.
	// GetDecision получает закэшированное решение авторизации.
	// Returns: allowed (the decision), found (whether it was in cache), error.
	// Возвращает: allowed (решение), found (было ли в кэше), error.
	GetDecision(ctx context.Context, userID int64, resource, action string) (allowed bool, found bool, err error)

	// SetDecision caches an authorization decision.
	// SetDecision кэширует решение авторизации.
	SetDecision(ctx context.Context, userID int64, resource, action string, allowed bool, expiration time.Duration) error

	// InvalidateUser invalidates all cached decisions for a specific user.
	// InvalidateUser инвалидирует все закэшированные решения для пользователя.
	// Call this when user roles change.
	// Вызывайте при изменении ролей пользователя.
	InvalidateUser(ctx context.Context, userID int64) error

	// InvalidateAll invalidates all cached authorization decisions.
	// InvalidateAll инвалидирует все закэшированные решения авторизации.
	// Call this when RBAC policies change.
	// Вызывайте при изменении политик RBAC.
	InvalidateAll(ctx context.Context) error
}

// TokenCache defines the interface for JWT token caching and blacklisting.
// TokenCache определяет интерфейс для кэширования и блокировки JWT токенов.
//
// Token blacklisting allows immediate token revocation before expiration,
// useful for logout or security incidents.
// Блокировка токенов позволяет немедленно отозвать токен до истечения,
// что полезно для выхода или инцидентов безопасности.
type TokenCache interface {
	// BlacklistToken adds a token to the blacklist.
	// BlacklistToken добавляет токен в чёрный список.
	// The token will be rejected until the blacklist entry expires.
	// Токен будет отклоняться, пока не истечёт запись в чёрном списке.
	BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error

	// IsBlacklisted checks if a token is in the blacklist.
	// IsBlacklisted проверяет, находится ли токен в чёрном списке.
	IsBlacklisted(ctx context.Context, tokenID string) (bool, error)
}

// RateLimitCache defines the interface for rate limiting operations.
// RateLimitCache определяет интерфейс для операций ограничения частоты запросов.
//
// Rate limiting protects the API from abuse by limiting the number
// of requests a client can make in a time window.
// Ограничение частоты защищает API от злоупотреблений, ограничивая
// количество запросов, которые клиент может сделать за период времени.
type RateLimitCache interface {
	// Increment increments a counter and returns the new value.
	// Increment увеличивает счётчик и возвращает новое значение.
	// Sets expiration if this is a new key.
	// Устанавливает время истечения, если это новый ключ.
	Increment(ctx context.Context, key string, expiration time.Duration) (int64, error)

	// GetCount retrieves the current count for a rate limit key.
	// GetCount получает текущее значение счётчика для ключа rate limit.
	GetCount(ctx context.Context, key string) (int64, error)

	// Reset resets the counter for a key (e.g., after successful login).
	// Reset сбрасывает счётчик для ключа (например, после успешного входа).
	Reset(ctx context.Context, key string) error
}

// RefreshTokenCache defines the interface for refresh token storage.
// RefreshTokenCache определяет интерфейс для хранения refresh токенов.
//
// Refresh tokens are stored in Redis to enable revocation and
// to track active sessions per user.
// Refresh токены хранятся в Redis для возможности отзыва и
// отслеживания активных сессий пользователя.
type RefreshTokenCache interface {
	// StoreRefreshToken stores a refresh token with user ID and expiration.
	// StoreRefreshToken сохраняет refresh токен с ID пользователя и временем истечения.
	StoreRefreshToken(ctx context.Context, tokenID string, userID int64, expiration time.Duration) error

	// GetRefreshToken retrieves the user ID associated with a refresh token.
	// GetRefreshToken получает ID пользователя, связанного с refresh токеном.
	// Returns userID and error. If token not found, returns 0 and error.
	// Возвращает userID и ошибку. Если токен не найден, возвращает 0 и ошибку.
	GetRefreshToken(ctx context.Context, tokenID string) (int64, error)

	// DeleteRefreshToken removes a refresh token (for logout).
	// DeleteRefreshToken удаляет refresh токен (для выхода).
	DeleteRefreshToken(ctx context.Context, tokenID string) error

	// DeleteUserRefreshTokens removes all refresh tokens for a user.
	// DeleteUserRefreshTokens удаляет все refresh токены пользователя.
	// Used when user changes password or for "logout from all devices".
	// Используется при смене пароля или для "выхода со всех устройств".
	DeleteUserRefreshTokens(ctx context.Context, userID int64) error

	// GetUserTokens retrieves all refresh token IDs for a user with their TTLs.
	// GetUserTokens получает все ID refresh токенов пользователя с их TTL.
	// Returns a map of tokenID -> TTL in seconds.
	// Возвращает карту tokenID -> TTL в секундах.
	GetUserTokens(ctx context.Context, userID int64) (map[string]int64, error)
}
