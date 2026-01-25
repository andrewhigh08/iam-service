// Package circuitbreaker provides a circuit breaker implementation for resilient service calls.
// Пакет circuitbreaker предоставляет реализацию circuit breaker для отказоустойчивых вызовов сервисов.
//
// The circuit breaker pattern prevents cascading failures by stopping requests.
// to a failing service and allowing it time to recover.
// Паттерн circuit breaker предотвращает каскадные сбои, останавливая запросы.
// к падающему сервису и давая ему время на восстановление.
package circuitbreaker

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// State represents the current state of the circuit breaker.
// State представляет текущее состояние circuit breaker.
type State int

const (
	// StateClosed means the circuit is closed and requests flow normally.
	// StateClosed означает, что цепь замкнута и запросы проходят нормально.
	StateClosed State = iota

	// StateOpen means the circuit is open and requests are blocked.
	// StateOpen означает, что цепь разомкнута и запросы блокируются.
	StateOpen

	// StateHalfOpen means the circuit is testing if the service has recovered.
	// StateHalfOpen означает, что цепь тестирует, восстановился ли сервис.
	StateHalfOpen
)

// String returns the string representation of the state.
// String возвращает строковое представление состояния.
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
// Config содержит конфигурацию для circuit breaker.
type Config struct {
	// Name identifies the circuit breaker (for logging/metrics).
	// Name идентифицирует circuit breaker (для логирования/метрик).
	Name string

	// MaxFailures is the number of failures before opening the circuit.
	// MaxFailures - количество сбоев до размыкания цепи.
	MaxFailures int

	// Timeout is the duration to wait before allowing a test request in half-open state.
	// Timeout - время ожидания перед разрешением тестового запроса в состоянии half-open.
	Timeout time.Duration

	// MaxHalfOpenRequests is the maximum number of requests allowed in half-open state.
	// MaxHalfOpenRequests - максимальное количество запросов в состоянии half-open.
	MaxHalfOpenRequests int

	// OnStateChange is called when the circuit breaker state changes.
	// OnStateChange вызывается при изменении состояния circuit breaker.
	OnStateChange func(name string, from, to State)
}

// DefaultConfig returns a default circuit breaker configuration.
// DefaultConfig возвращает конфигурацию circuit breaker по умолчанию.
func DefaultConfig(name string) Config {
	return Config{
		Name:                name,
		MaxFailures:         5,
		Timeout:             30 * time.Second,
		MaxHalfOpenRequests: 1,
	}
}

// CircuitBreaker implements the circuit breaker pattern.
// CircuitBreaker реализует паттерн circuit breaker.
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
// New создаёт новый circuit breaker с заданной конфигурацией.
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
// Execute запускает заданную функцию с защитой circuit breaker.
func (cb *CircuitBreaker) Execute(ctx context.Context, fn func(context.Context) error) error {
	if err := cb.canExecute(); err != nil {
		return err
	}

	err := fn(ctx)

	cb.recordResult(err)

	return err
}

// ExecuteWithResult runs a function that returns a value with circuit breaker protection.
// ExecuteWithResult запускает функцию, возвращающую значение, с защитой circuit breaker.
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
// canExecute проверяет, может ли запрос быть выполнен на основе текущего состояния.
func (cb *CircuitBreaker) canExecute() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case StateClosed:
		return nil

	case StateOpen:
		// Check if timeout has passed. / Проверяем, прошёл ли таймаут.
		if time.Since(cb.lastFailureTime) > cb.config.Timeout {
			cb.setState(StateHalfOpen)
			cb.halfOpenRequests = 1
			return nil
		}
		return apperror.ServiceUnavailable("service temporarily unavailable (circuit breaker open)")

	case StateHalfOpen:
		// Allow limited requests in half-open state. / Разрешаем ограниченное количество запросов.
		if cb.halfOpenRequests < cb.config.MaxHalfOpenRequests {
			cb.halfOpenRequests++
			return nil
		}
		return apperror.ServiceUnavailable("service temporarily unavailable (circuit breaker half-open)")
	}

	return nil
}

// recordResult records the result of an execution.
// recordResult записывает результат выполнения.
func (cb *CircuitBreaker) recordResult(err error) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil && cb.isTransientError(err) {
		cb.onFailure()
	} else if err == nil {
		cb.onSuccess()
	}
	// Non-transient errors (e.g., validation errors) don't affect the circuit.
	// Непереходные ошибки (например, ошибки валидации) не влияют на circuit.
}

// isTransientError determines if an error is transient and should count towards the failure threshold.
// isTransientError определяет, является ли ошибка переходной и должна ли учитываться в пороге сбоев.
func (cb *CircuitBreaker) isTransientError(err error) bool {
	if err == nil {
		return false
	}

	// Check if it's an AppError. / Проверяем, является ли это AppError.
	var appErr *apperror.AppError
	if errors.As(err, &appErr) {
		// These error codes indicate transient failures.
		// Эти коды ошибок указывают на переходные сбои.
		switch appErr.Code {
		case apperror.CodeInternal, apperror.CodeServiceUnavailable:
			return true
		default:
			// Business errors (NOT_FOUND, VALIDATION_ERROR, etc.) are not transient.
			// Бизнес-ошибки (NOT_FOUND, VALIDATION_ERROR и т.д.) не являются переходными.
			return false
		}
	}

	// For non-AppError errors, consider them transient.
	// Для ошибок, не являющихся AppError, считаем их переходными.
	return true
}

// onFailure handles a failed execution.
// onFailure обрабатывает неудачное выполнение.
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
		// Любой сбой в состоянии half-open снова размыкает цепь.
		cb.setState(StateOpen)
	case StateOpen:
		// Already open, nothing to do.
		// Уже открыт, ничего не делаем.
	}
}

// onSuccess handles a successful execution.
// onSuccess обрабатывает успешное выполнение.
func (cb *CircuitBreaker) onSuccess() {
	switch cb.state {
	case StateClosed:
		cb.failures = 0
	case StateHalfOpen:
		cb.successes++
		// If enough successes in half-open state, close the circuit.
		// Если достаточно успехов в состоянии half-open, замыкаем цепь.
		if cb.successes >= cb.config.MaxHalfOpenRequests {
			cb.setState(StateClosed)
		}
	case StateOpen:
		// Should not happen - requests blocked in open state.
		// Не должно происходить - запросы блокируются в открытом состоянии.
	}
}

// setState changes the state and calls the callback if configured.
// setState меняет состояние и вызывает callback, если настроен.
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
		// Вызываем callback вне блокировки для предотвращения deadlock.
		go cb.config.OnStateChange(cb.config.Name, oldState, newState)
	}
}

// State returns the current state of the circuit breaker.
// State возвращает текущее состояние circuit breaker.
func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// Failures returns the current failure count.
// Failures возвращает текущее количество сбоев.
func (cb *CircuitBreaker) Failures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failures
}

// Reset resets the circuit breaker to closed state.
// Reset сбрасывает circuit breaker в закрытое состояние.
func (cb *CircuitBreaker) Reset() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = StateClosed
	cb.failures = 0
	cb.successes = 0
	cb.halfOpenRequests = 0
}
