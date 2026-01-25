package circuitbreaker_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/circuitbreaker"
)

func TestCircuitBreaker_InitialState(t *testing.T) {
	cb := circuitbreaker.New(circuitbreaker.DefaultConfig("test"))

	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
	assert.Equal(t, 0, cb.Failures())
}

func TestCircuitBreaker_SuccessfulExecution(t *testing.T) {
	cb := circuitbreaker.New(circuitbreaker.DefaultConfig("test"))
	ctx := context.Background()

	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})

	assert.NoError(t, err)
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
	assert.Equal(t, 0, cb.Failures())
}

func TestCircuitBreaker_TransientFailuresOpenCircuit(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 3,
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("database connection failed", errors.New("connection refused"))

	// First two failures - circuit still closed
	for i := 0; i < 2; i++ {
		err := cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
		assert.Error(t, err)
		assert.Equal(t, circuitbreaker.StateClosed, cb.State())
	}

	// Third failure - circuit opens
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return transientErr
	})
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Next execution should fail immediately without calling function
	callCount := 0
	err = cb.Execute(ctx, func(ctx context.Context) error {
		callCount++
		return nil
	})
	assert.Error(t, err)
	assert.Equal(t, 0, callCount) // Function was not called
	assert.Contains(t, err.Error(), "circuit breaker open")
}

func TestCircuitBreaker_NonTransientErrorsDoNotOpenCircuit(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	// Business errors (NOT_FOUND, VALIDATION_ERROR) should not count as failures
	businessErr := apperror.NotFound("user", 123)

	for i := 0; i < 10; i++ {
		err := cb.Execute(ctx, func(ctx context.Context) error {
			return businessErr
		})
		assert.Error(t, err)
	}

	// Circuit should still be closed
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
}

func TestCircuitBreaker_HalfOpenState(t *testing.T) {
	config := circuitbreaker.Config{
		Name:                "test",
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("db error", errors.New("timeout"))

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
	}
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Next request should transition to half-open and execute
	callCount := 0
	err := cb.Execute(ctx, func(ctx context.Context) error {
		callCount++
		return nil // Success
	})
	assert.NoError(t, err)
	assert.Equal(t, 1, callCount)
	assert.Equal(t, circuitbreaker.StateClosed, cb.State()) // Success closes circuit
}

func TestCircuitBreaker_HalfOpenFailureReopensCircuit(t *testing.T) {
	config := circuitbreaker.Config{
		Name:                "test",
		MaxFailures:         2,
		Timeout:             50 * time.Millisecond,
		MaxHalfOpenRequests: 1,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("db error", errors.New("timeout"))

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
	}
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Wait for timeout
	time.Sleep(60 * time.Millisecond)

	// Half-open request fails -> circuit reopens
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return transientErr
	})
	assert.Error(t, err)
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())
}

func TestCircuitBreaker_Reset(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("error", errors.New("err"))

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
	}
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Reset
	cb.Reset()
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
	assert.Equal(t, 0, cb.Failures())

	// Should be able to execute again
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	assert.NoError(t, err)
}

func TestCircuitBreaker_ExecuteWithResult(t *testing.T) {
	cb := circuitbreaker.New(circuitbreaker.DefaultConfig("test"))
	ctx := context.Background()

	result, err := circuitbreaker.ExecuteWithResult(ctx, cb, func(ctx context.Context) (string, error) {
		return "success", nil
	})

	assert.NoError(t, err)
	assert.Equal(t, "success", result)
}

func TestCircuitBreaker_ExecuteWithResult_Error(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 2,
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("error", errors.New("err"))

	// Open the circuit
	for i := 0; i < 2; i++ {
		_, _ = circuitbreaker.ExecuteWithResult(ctx, cb, func(ctx context.Context) (int, error) {
			return 0, transientErr
		})
	}
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// Circuit open - should return zero value and error
	result, err := circuitbreaker.ExecuteWithResult(ctx, cb, func(ctx context.Context) (int, error) {
		return 42, nil
	})

	assert.Error(t, err)
	assert.Equal(t, 0, result) // Zero value for int
}

func TestCircuitBreaker_StateChangeCallback(t *testing.T) {
	var stateChanges []struct {
		from circuitbreaker.State
		to   circuitbreaker.State
	}
	var mu sync.Mutex

	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 2,
		Timeout:     50 * time.Millisecond,
		OnStateChange: func(name string, from, to circuitbreaker.State) {
			mu.Lock()
			stateChanges = append(stateChanges, struct {
				from circuitbreaker.State
				to   circuitbreaker.State
			}{from, to})
			mu.Unlock()
		},
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("error", errors.New("err"))

	// Open the circuit
	for i := 0; i < 2; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
	}

	// Wait for callback goroutine
	time.Sleep(10 * time.Millisecond)

	mu.Lock()
	require.Len(t, stateChanges, 1)
	assert.Equal(t, circuitbreaker.StateClosed, stateChanges[0].from)
	assert.Equal(t, circuitbreaker.StateOpen, stateChanges[0].to)
	mu.Unlock()
}

func TestCircuitBreaker_ConcurrentAccess(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 100, // High threshold so we don't open during test
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	var successCount int64
	var wg sync.WaitGroup

	// Run 100 concurrent requests
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := cb.Execute(ctx, func(ctx context.Context) error {
				return nil
			})
			if err == nil {
				atomic.AddInt64(&successCount, 1)
			}
		}()
	}

	wg.Wait()
	assert.Equal(t, int64(100), successCount)
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
}

func TestCircuitBreaker_SuccessResetsFailureCount(t *testing.T) {
	config := circuitbreaker.Config{
		Name:        "test",
		MaxFailures: 3,
		Timeout:     100 * time.Millisecond,
	}
	cb := circuitbreaker.New(config)
	ctx := context.Background()

	transientErr := apperror.Internal("error", errors.New("err"))

	// Two failures
	for i := 0; i < 2; i++ {
		_ = cb.Execute(ctx, func(ctx context.Context) error {
			return transientErr
		})
	}
	assert.Equal(t, 2, cb.Failures())

	// One success resets failures
	err := cb.Execute(ctx, func(ctx context.Context) error {
		return nil
	})
	assert.NoError(t, err)
	assert.Equal(t, 0, cb.Failures())

	// Circuit should still be closed
	assert.Equal(t, circuitbreaker.StateClosed, cb.State())
}

func TestState_String(t *testing.T) {
	tests := []struct {
		state    circuitbreaker.State
		expected string
	}{
		{circuitbreaker.StateClosed, "closed"},
		{circuitbreaker.StateOpen, "open"},
		{circuitbreaker.StateHalfOpen, "half-open"},
		{circuitbreaker.State(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.String())
		})
	}
}

func TestDefaultConfig(t *testing.T) {
	config := circuitbreaker.DefaultConfig("my-service")

	assert.Equal(t, "my-service", config.Name)
	assert.Equal(t, 5, config.MaxFailures)
	assert.Equal(t, 30*time.Second, config.Timeout)
	assert.Equal(t, 1, config.MaxHalfOpenRequests)
	assert.Nil(t, config.OnStateChange)
}
