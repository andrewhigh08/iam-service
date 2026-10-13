// Package port defines interfaces (ports) for the application's external dependencies.
package port

import (
	"context"
	"time"
)

// Cache defines the interface for generic caching operations.
//
// This interface provides a simple key-value cache abstraction
// that can be implemented by Redis, Memcached, or in-memory stores.
type Cache interface {
	// Get retrieves a value from the cache by key.
	// Returns empty string and error if key doesn't exist.
	Get(ctx context.Context, key string) (string, error)

	// Set stores a value in the cache with an expiration time.
	Set(ctx context.Context, key string, value string, expiration time.Duration) error

	// Delete removes a value from the cache.
	Delete(ctx context.Context, key string) error

	// DeleteByPattern removes all values matching a glob pattern.
	// Example: "user:*" deletes all keys starting with "user:"
	DeleteByPattern(ctx context.Context, pattern string) error

	// Exists checks if a key exists in the cache.
	Exists(ctx context.Context, key string) (bool, error)
}

// AuthorizationCache defines the interface for caching authorization decisions.
//
// Caching authorization decisions significantly improves performance
// by avoiding repeated database lookups for the same access checks.
type AuthorizationCache interface {
	// GetDecision retrieves a cached authorization decision.
	// Returns: allowed (the decision), found (whether it was in cache), error.
	GetDecision(ctx context.Context, userID int64, resource, action string) (allowed bool, found bool, err error)

	// SetDecision caches an authorization decision.
	SetDecision(ctx context.Context, userID int64, resource, action string, allowed bool, expiration time.Duration) error

	// InvalidateUser invalidates all cached decisions for a specific user.
	// Call this when user roles change.
	InvalidateUser(ctx context.Context, userID int64) error

	// InvalidateAll invalidates all cached authorization decisions.
	// Call this when RBAC policies change.
	InvalidateAll(ctx context.Context) error
}

// TokenCache defines the interface for JWT token caching and blacklisting.
//
// Token blacklisting allows immediate token revocation before expiration,
// useful for logout or security incidents.
type TokenCache interface {
	// BlacklistToken adds a token to the blacklist.
	// The token will be rejected until the blacklist entry expires.
	BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error

	// IsBlacklisted checks if a token is in the blacklist.
	IsBlacklisted(ctx context.Context, tokenID string) (bool, error)
}

// RateLimitCache defines the interface for rate limiting operations.
//
// Rate limiting protects the API from abuse by limiting the number
// of requests a client can make in a time window.
type RateLimitCache interface {
	// Increment increments a counter and returns the new value.
	// Sets expiration if this is a new key.
	Increment(ctx context.Context, key string, expiration time.Duration) (int64, error)

	// GetCount retrieves the current count for a rate limit key.
	GetCount(ctx context.Context, key string) (int64, error)

	// Reset resets the counter for a key (e.g., after successful login).
	Reset(ctx context.Context, key string) error
}

// RefreshTokenCache defines the interface for refresh token storage.
//
// Refresh tokens are stored in Redis to enable revocation and
// to track active sessions per user.
type RefreshTokenCache interface {
	// StoreRefreshToken stores a refresh token with user ID and expiration.
	StoreRefreshToken(ctx context.Context, tokenID string, userID int64, expiration time.Duration) error

	// GetRefreshToken retrieves the user ID associated with a refresh token.
	// Returns userID and error. If token not found, returns 0 and error.
	GetRefreshToken(ctx context.Context, tokenID string) (int64, error)

	// DeleteRefreshToken removes a refresh token (for logout).
	DeleteRefreshToken(ctx context.Context, tokenID string) error

	// DeleteUserRefreshTokens removes all refresh tokens for a user.
	// Used when user changes password or for "logout from all devices".
	DeleteUserRefreshTokens(ctx context.Context, userID int64) error

	// GetUserTokens retrieves all refresh token IDs for a user with their TTLs.
	// Returns a map of tokenID -> TTL in seconds.
	GetUserTokens(ctx context.Context, userID int64) (map[string]int64, error)
}
