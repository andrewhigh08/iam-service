// Package circuitbreaker provides a circuit breaker implementation for resilient service calls.
//
// The circuit breaker pattern prevents cascading failures by stopping requests.
// to a failing service and allowing it time to recover.
package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// State represents the current state of the circuit breaker.
type State int

const (
	// StateClosed means the circuit is closed and requests flow normally.
	StateClosed State = iota

	// StateOpen means the circuit is open and requests are blocked.
	StateOpen

	// StateHalfOpen means the circuit is testing if the service has recovered.
	StateHalfOpen
)

// String returns the string representation of the state.
func (s State) String() string {
	switch s {
	case StateClosed:
		return "closed"
	case StateOpen:
		return "open"
	case StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

// Config holds the configuration for a circuit breaker.
type Config struct {
	// Name identifies the circuit breaker (for logging/metrics).
	Name string

	// MaxFailures is the number of failures before opening the circuit.
	MaxFailures int

	// Timeout is the duration to wait before allowing a test request in half-open state.
	Timeout time.Duration

	// MaxHalfOpenRequests is the maximum number of requests allowed in half-open state.
	MaxHalfOpenRequests int

	// OnStateChange is called when the circuit breaker state changes.
	OnStateChange func(name string, from, to State)
}

// DefaultConfig returns a default circuit breaker configuration.
func DefaultConfig(name string) Config {
	return Config{
		Name:                name,
		MaxFailures:         5,
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern.
type CircuitBreaker struct {
	config Config

	mu               sync.RWMutex
	state            State
	failures         int
	successes        int
	lastFailureTime  time.Time
	halfOpenRequests int
}

// New creates a new circuit breaker with the given configuration.
func New(config Config) *CircuitBreaker {
	if config.MaxFailures <= 0 {
		config.MaxFailures = 5
	}
	if config.Timeout <= 0 {
		config.Timeout = 30 * time.Second
	}
	if config.MaxHalfOpenRequests <= 0 {
		config.MaxHalfOpenRequests = 1
	}

	return &CircuitBreaker{
		config: config,
		state:  StateClosed,
	}
}

// Execute runs the given function with circuit breaker protection.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.canExecute(); err != nil {
		return err
	}

	err := fn(ctx)

	cb.recordResult(err)

	return err
}

// ExecuteWithResult runs a function that returns a value with circuit breaker protection.
func ExecuteWithResult[T any](ctx context.Context, cb *CircuitBreaker, fn func(context.Context) (T, error)) (T, error) {
	var zero T

	if err := cb.canExecute(); err != nil {
		return zero, err
	}

	result, err := fn(ctx)

	cb.recordResult(err)

	return result, err
}

// canExecute checks if a request can be executed based on the current state.
func (cb *CircuitBreaker) canExecute() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		// Check if timeout has passed.
		if time.Since(cb.lastFailureTime) > cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.halfOpenRequests = 1
			return nil
		}
		return apperror.ServiceUnavailable("service temporarily unavailable (circuit breaker open)")

	case StateHalfOpen:
		// Allow limited requests in half-open state.
		if cb.halfOpenRequests < cb.config.MaxHalfOpenRequests {
			cb.halfOpenRequests++
			return nil
		}
		return apperror.ServiceUnavailable("service temporarily unavailable (circuit breaker half-open)")
	}

	return nil
}

// recordResult records the result of an execution.
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil && cb.isTransientError(err) {
		cb.onFailure()
	} else if err == nil {
		cb.onSuccess()
	}
	// Non-transient errors (e.g., validation errors) don't affect the circuit.
}

// isTransientError determines if an error is transient and should count towards the failure threshold.
func (cb *CircuitBreaker) isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's an AppError.
	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		// These error codes indicate transient failures.
		switch appErr.Code {
		case apperror.CodeInternal, apperror.CodeServiceUnavailable:
			return true
		default:
			// Business errors (NOT_FOUND, VALIDATION_ERROR, etc.) are not transient.
			return false
		}
	}

	// For non-AppError errors, consider them transient.
	return true
}

// onFailure handles a failed execution.
func (cb *CircuitBreaker) onFailure() {
	cb.failures++
	cb.lastFailureTime = time.Now()

	switch cb.state {
	case StateClosed:
		if cb.failures >= cb.config.MaxFailures {
			cb.setState(StateOpen)
		}
	case StateHalfOpen:
		// Any failure in half-open state opens the circuit again.
		cb.setState(StateOpen)
	case StateOpen:
		// Already open, nothing to do.
	}
}

// onSuccess handles a successful execution.
func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case StateClosed:
		cb.failures = 0
	case StateHalfOpen:
		cb.successes++
		// If enough successes in half-open state, close the circuit.
		if cb.successes >= cb.config.MaxHalfOpenRequests {
			cb.setState(StateClosed)
		}
	case StateOpen:
		// Should not happen - requests blocked in open state.
	}
}

// setState changes the state and calls the callback if configured.
func (cb *CircuitBreaker) setState(newState State) {
	if cb.state == newState {
		return
	}

	oldState := cb.state
	cb.state = newState
	cb.failures = 0
	cb.successes = 0
	cb.halfOpenRequests = 0

	if cb.config.OnStateChange != nil {
		// Call callback outside of lock to prevent deadlocks.
		go cb.config.OnStateChange(cb.config.Name, oldState, newState)
	}
}

// State returns the current state of the circuit breaker.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Failures returns the current failure count.
func (cb *CircuitBreaker) Failures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// Reset resets the circuit breaker to closed state.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.halfOpenRequests = 0
}
