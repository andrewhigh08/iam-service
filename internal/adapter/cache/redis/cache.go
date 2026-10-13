// Package redis provides Redis-based cache implementations.
//
// This package implements all cache interfaces defined in port package
// using Redis as the underlying storage.
package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// Cache implements port.Cache interface using Redis.
//
// Provides basic key-value caching operations with expiration support.
type Cache struct {
	client *redis.Client // Redis client
}

// NewCache creates a new Redis Cache instance.
func NewCache(client *redis.Client) *Cache {
	return &Cache{client: client}
}

// Get retrieves a value from the cache by key.
// Returns empty string and error if key doesn't exist.
func (c *Cache) Get(ctx context.Context, key string) (string, error) {
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return "", apperror.NotFound("cache key", key)
		}
		return "", apperror.Internal("failed to get cache value", err)
	}
	return val, nil
}

// Set stores a value in the cache with an expiration time.
func (c *Cache) Set(ctx context.Context, key, value string, expiration time.Duration) error {
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return apperror.Internal("failed to set cache value", err)
	}
	return nil
}

// Delete removes a value from the cache.
func (c *Cache) Delete(ctx context.Context, key string) error {
	if err := c.client.Del(ctx, key).Err(); err != nil {
		return apperror.Internal("failed to delete cache key", err)
	}
	return nil
}

// DeleteByPattern removes all values matching a glob pattern.
// Uses SCAN to iterate through matching keys safely.
func (c *Cache) DeleteByPattern(ctx context.Context, pattern string) error {
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			return apperror.Internal("failed to delete cache key", err)
		}
	}
	if err := iter.Err(); err != nil {
		return apperror.Internal("failed to scan cache keys", err)
	}
	return nil
}

// Exists checks if a key exists in the cache.
func (c *Cache) Exists(ctx context.Context, key string) (bool, error) {
	count, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, apperror.Internal("failed to check cache key existence", err)
	}
	return count > 0, nil
}

// AuthorizationCache implements port.AuthorizationCache using Redis.
//
// Caches RBAC authorization decisions to improve performance by avoiding
// repeated database lookups for the same access checks.
type AuthorizationCache struct {
	client *redis.Client // Redis client
	prefix string        // Key prefix
}

// NewAuthorizationCache creates a new AuthorizationCache instance.
func NewAuthorizationCache(client *redis.Client) *AuthorizationCache {
	return &AuthorizationCache{
		client: client,
		prefix: "authz:decision",
	}
}

// GetDecision retrieves a cached authorization decision.
// Returns: allowed (the decision), found (whether it was in cache), error.
func (c *AuthorizationCache) GetDecision(ctx context.Context, userID int64, resource, action string) (allowed, found bool, err error) {
	key := c.buildKey(userID, resource, action)
	val, err := c.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, false, nil // Not found in cache
		}
		return false, false, apperror.Internal("failed to get authz decision", err)
	}
	return val == "1", true, nil // "1" = allowed, "0" = denied
}

// SetDecision caches an authorization decision.
func (c *AuthorizationCache) SetDecision(ctx context.Context, userID int64, resource, action string, allowed bool, expiration time.Duration) error {
	key := c.buildKey(userID, resource, action)
	value := "0" // denied
	if allowed {
		value = "1" // allowed
	}
	if err := c.client.Set(ctx, key, value, expiration).Err(); err != nil {
		return apperror.Internal("failed to set authz decision", err)
	}
	return nil
}

// InvalidateUser invalidates all cached decisions for a specific user.
// Call this when user roles change.
func (c *AuthorizationCache) InvalidateUser(ctx context.Context, userID int64) error {
	pattern := fmt.Sprintf("%s:%d:*", c.prefix, userID)
	return c.deleteByPattern(ctx, pattern)
}

// InvalidateAll invalidates all cached authorization decisions.
// Call this when RBAC policies change.
func (c *AuthorizationCache) InvalidateAll(ctx context.Context) error {
	pattern := fmt.Sprintf("%s:*", c.prefix)
	return c.deleteByPattern(ctx, pattern)
}

// buildKey constructs a cache key for authorization decision.
func (c *AuthorizationCache) buildKey(userID int64, resource, action string) string {
	return fmt.Sprintf("%s:%d:%s:%s", c.prefix, userID, resource, action)
}

// deleteByPattern deletes all keys matching the given pattern.
func (c *AuthorizationCache) deleteByPattern(ctx context.Context, pattern string) error {
	iter := c.client.Scan(ctx, 0, pattern, 100).Iterator()
	for iter.Next(ctx) {
		if err := c.client.Del(ctx, iter.Val()).Err(); err != nil {
			return apperror.Internal("failed to delete cache key", err)
		}
	}
	return iter.Err()
}

// RateLimitCache implements port.RateLimitCache using Redis.
//
// Provides rate limiting functionality using Redis atomic counters.
type RateLimitCache struct {
	client *redis.Client // Redis client
	prefix string        // Key prefix
}

// NewRateLimitCache creates a new RateLimitCache instance.
func NewRateLimitCache(client *redis.Client) *RateLimitCache {
	return &RateLimitCache{
		client: client,
		prefix: "ratelimit",
	}
}

// Increment increments a counter and returns the new value.
// Sets expiration if this is a new key.
func (c *RateLimitCache) Increment(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	fullKey := fmt.Sprintf("%s:%s", c.prefix, key)

	// Use pipeline for atomic INCR + EXPIRE
	pipe := c.client.Pipeline()
	incr := pipe.Incr(ctx, fullKey)
	pipe.Expire(ctx, fullKey, expiration)

	_, err := pipe.Exec(ctx)
	if err != nil {
		return 0, apperror.Internal("failed to increment rate limit counter", err)
	}

	return incr.Val(), nil
}

// GetCount retrieves the current count for a rate limit key.
func (c *RateLimitCache) GetCount(ctx context.Context, key string) (int64, error) {
	fullKey := fmt.Sprintf("%s:%s", c.prefix, key)
	val, err := c.client.Get(ctx, fullKey).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, nil // Key doesn't exist, count is 0
		}
		return 0, apperror.Internal("failed to get rate limit count", err)
	}
	return val, nil
}

// Reset resets the counter for a key.
// Use this after successful login to reset failed attempt counter.
func (c *RateLimitCache) Reset(ctx context.Context, key string) error {
	fullKey := fmt.Sprintf("%s:%s", c.prefix, key)
	if err := c.client.Del(ctx, fullKey).Err(); err != nil {
		return apperror.Internal("failed to reset rate limit counter", err)
	}
	return nil
}

// TokenCache implements port.TokenCache using Redis.
//
// Provides token blacklisting functionality for immediate token revocation.
type TokenCache struct {
	client *redis.Client // Redis client
	prefix string        // Key prefix
}

// NewTokenCache creates a new TokenCache instance.
func NewTokenCache(client *redis.Client) *TokenCache {
	return &TokenCache{
		client: client,
		prefix: "token:blacklist",
	}
}

// BlacklistToken adds a token to the blacklist.
// The token will be rejected until the blacklist entry expires.
func (c *TokenCache) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	key := fmt.Sprintf("%s:%s", c.prefix, tokenID)
	if err := c.client.Set(ctx, key, "1", expiration).Err(); err != nil {
		return apperror.Internal("failed to blacklist token", err)
	}
	return nil
}

// IsBlacklisted checks if a token is in the blacklist.
func (c *TokenCache) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	key := fmt.Sprintf("%s:%s", c.prefix, tokenID)
	exists, err := c.client.Exists(ctx, key).Result()
	if err != nil {
		return false, apperror.Internal("failed to check token blacklist", err)
	}
	return exists > 0, nil
}

// RefreshTokenCache implements port.RefreshTokenCache using Redis.
//
// Stores refresh tokens with user associations for token refresh and revocation.
type RefreshTokenCache struct {
	client *redis.Client // Redis client
	prefix string        // Key prefix
}

// NewRefreshTokenCache creates a new RefreshTokenCache instance.
func NewRefreshTokenCache(client *redis.Client) *RefreshTokenCache {
	return &RefreshTokenCache{
		client: client,
		prefix: "refresh_token",
	}
}

// StoreRefreshToken stores a refresh token with user ID and expiration.
func (c *RefreshTokenCache) StoreRefreshToken(ctx context.Context, tokenID string, userID int64, expiration time.Duration) error {
	// Store token -> userID mapping
	tokenKey := fmt.Sprintf("%s:%s", c.prefix, tokenID)
	if err := c.client.Set(ctx, tokenKey, userID, expiration).Err(); err != nil {
		return apperror.Internal("failed to store refresh token", err)
	}

	// Add tokenID to user's token set for easy revocation
	userKey := fmt.Sprintf("%s:user:%d", c.prefix, userID)
	if err := c.client.SAdd(ctx, userKey, tokenID).Err(); err != nil {
		return apperror.Internal("failed to add token to user set", err)
	}

	return nil
}

// GetRefreshToken retrieves the user ID associated with a refresh token.
// Returns userID and error. If token not found, returns 0 and error.
func (c *RefreshTokenCache) GetRefreshToken(ctx context.Context, tokenID string) (int64, error) {
	key := fmt.Sprintf("%s:%s", c.prefix, tokenID)
	userID, err := c.client.Get(ctx, key).Int64()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return 0, apperror.NotFound("refresh token", tokenID)
		}
		return 0, apperror.Internal("failed to get refresh token", err)
	}
	return userID, nil
}

// DeleteRefreshToken removes a refresh token (for logout).
func (c *RefreshTokenCache) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	key := fmt.Sprintf("%s:%s", c.prefix, tokenID)

	// Get userID to remove from user's token set
	userID, err := c.client.Get(ctx, key).Int64()
	if err == nil {
		userKey := fmt.Sprintf("%s:user:%d", c.prefix, userID)
		c.client.SRem(ctx, userKey, tokenID)
	}

	if err := c.client.Del(ctx, key).Err(); err != nil {
		return apperror.Internal("failed to delete refresh token", err)
	}
	return nil
}

// DeleteUserRefreshTokens removes all refresh tokens for a user.
// Used when user changes password or for "logout from all devices".
func (c *RefreshTokenCache) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	userKey := fmt.Sprintf("%s:user:%d", c.prefix, userID)

	// Get all token IDs for this user
	tokenIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return apperror.Internal("failed to get user refresh tokens", err)
	}

	// Delete each token
	for _, tokenID := range tokenIDs {
		tokenKey := fmt.Sprintf("%s:%s", c.prefix, tokenID)
		c.client.Del(ctx, tokenKey)
	}

	// Delete the user's token set
	if err := c.client.Del(ctx, userKey).Err(); err != nil {
		return apperror.Internal("failed to delete user token set", err)
	}

	return nil
}

// GetUserTokens retrieves all refresh token IDs for a user with their TTLs.
// Returns a map of tokenID -> TTL in seconds.
func (c *RefreshTokenCache) GetUserTokens(ctx context.Context, userID int64) (map[string]int64, error) {
	userKey := fmt.Sprintf("%s:user:%d", c.prefix, userID)

	// Get all token IDs for this user
	tokenIDs, err := c.client.SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, apperror.Internal("failed to get user refresh tokens", err)
	}

	result := make(map[string]int64)

	// Get TTL for each token
	for _, tokenID := range tokenIDs {
		tokenKey := fmt.Sprintf("%s:%s", c.prefix, tokenID)
		ttl, err := c.client.TTL(ctx, tokenKey).Result()
		if err != nil {
			continue // Skip tokens with errors
		}
		// Only include valid tokens (TTL > 0)
		if ttl > 0 {
			result[tokenID] = int64(ttl.Seconds())
		} else {
			// Token expired, clean up from set
			c.client.SRem(ctx, userKey, tokenID)
		}
	}

	return result, nil
}
