package redisstore

import "errors"

// Invariant violations reported by the stores; they are wrapped in apperror.Internal.
var (
	errEmptyTokenHash = errors.New("session token hash is empty")
	errNonPositiveTTL = errors.New("ttl must be positive")
)
