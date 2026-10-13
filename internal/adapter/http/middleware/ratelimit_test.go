package middleware

import (
	"context"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/time/rate"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// entryKeys returns the keys currently tracked by the limiter.
func (l *IPRateLimiter) entryKeys() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	keys := make([]string, 0, len(l.entries))
	for k := range l.entries {
		keys = append(keys, k)
	}
	return keys
}

// countingRouter serves GET /ping behind mw and counts how often the handler ran.
func countingRouter(mw gin.HandlerFunc) (*gin.Engine, *atomic.Int64) {
	var hits atomic.Int64
	r := gin.New()
	r.GET("/ping", mw, func(c *gin.Context) {
		hits.Add(1)
		okHandler(c)
	})
	return r, &hits
}

// getFrom sends GET /ping to r from the given client IP.
func getFrom(t *testing.T, r http.Handler, ip string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ping", http.NoBody)
	req.RemoteAddr = ip + ":12345"
	return serve(r, req)
}

// testConfig is a permissive configuration for tests that exercise the bookkeeping, not the limits.
func testConfig() RateLimitConfig {
	return RateLimitConfig{RPS: 100, Burst: 200, LoginPerMinute: 5, LoginBurst: 10}
}

func TestClientKey(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		ip   string
		want string
	}{
		{"ipv4", "203.0.113.7", "203.0.113.7"},
		{"ipv4-mapped ipv6", "::ffff:203.0.113.7", "203.0.113.7"},
		{"ipv6 is keyed by its /64", "2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"},
		{"ipv6 host bits do not matter", "2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"ipv6 zone is dropped", "fe80::1%eth0", "fe80::/64"},
		{"not an ip", "unknown", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, clientKey(tt.ip))
		})
	}
}

func TestMiddleware_IPv6ClientsShareTheirPrefixBucket(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: 1})
	r, _ := countingRouter(l.Middleware())

	assert.Equal(t, http.StatusOK, getFrom(t, r, "[2001:db8:1:2::1]").Code)
	assert.Equal(t, http.StatusTooManyRequests, getFrom(t, r, "[2001:db8:1:2::2]").Code, "another address of the same /64 shares the bucket")
	assert.Equal(t, http.StatusOK, getFrom(t, r, "[2001:db8:1:3::1]").Code, "another /64 has its own bucket")
	assert.ElementsMatch(t, []string{"2001:db8:1:2::/64", "2001:db8:1:3::/64"}, l.entryKeys())
}

func TestLimiter_NeverGrowsBeyondTheCap(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(testConfig())
	l.maxEntries = 3
	now := time.Now()
	for _, key := range []string{"a", "b", "c", "d", "e"} {
		l.limiter(key, 1, 1, now)
	}

	assert.Len(t, l.entryKeys(), 3)
	assert.Contains(t, l.entryKeys(), "e", "the newest client is always admitted")
}

func TestMiddleware_AllowsBurstThenRejectsWithRetryAfter(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0.5, Burst: 3, LoginPerMinute: 5, LoginBurst: 10})
	r, hits := countingRouter(l.Middleware())

	for i := range 3 {
		rec := getFrom(t, r, "10.0.0.1")
		assert.Equalf(t, http.StatusOK, rec.Code, "request %d is within the burst", i+1)
		assert.Empty(t, rec.Header().Get("Retry-After"))
	}

	rec := getFrom(t, r, "10.0.0.1")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "2", rec.Header().Get("Retry-After"), "one token takes two seconds at 0.5 rps")
	assert.Equal(t, int64(3), hits.Load(), "the rejected request never reaches the handler")

	env := decodeEnvelope(t, rec)
	assert.False(t, env.Success)
	require.NotNil(t, env.Error)
	assert.Equal(t, apperror.CodeTooManyRequests, env.Error.Code)
	assert.Equal(t, "rate limit exceeded", env.Error.Message)
	assert.InDelta(t, 2, env.Error.Details["retry_after_seconds"], 0)
}

func TestMiddleware_ZeroRateDeniesOnceTheBurstIsSpent(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: 2})
	r, _ := countingRouter(l.Middleware())

	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code)
	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code)

	rec := getFrom(t, r, "10.0.0.1")
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	retryAfter, err := strconv.Atoi(rec.Header().Get("Retry-After"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, retryAfter, 1)
}

func TestMiddleware_KeepsSeparateBucketsPerIP(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: 1})
	r, _ := countingRouter(l.Middleware())

	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code)
	assert.Equal(t, http.StatusTooManyRequests, getFrom(t, r, "10.0.0.1").Code)

	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.2").Code, "another client has its own bucket")
	assert.Equal(t, http.StatusTooManyRequests, getFrom(t, r, "10.0.0.2").Code)
	assert.Equal(t, http.StatusTooManyRequests, getFrom(t, r, "10.0.0.1").Code, "the first client is still limited")

	assert.ElementsMatch(t, []string{"10.0.0.1", "10.0.0.2"}, l.entryKeys())
}

func TestLoginMiddleware_IsStricterAndTrackedSeparately(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 100, Burst: 10, LoginPerMinute: 6, LoginBurst: 2})
	r := gin.New()
	r.POST("/login", l.Middleware(), l.LoginMiddleware(), okHandler)
	r.GET("/ping", l.Middleware(), okHandler)

	login := func() *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/login", http.NoBody)
		req.RemoteAddr = "10.0.0.1:12345"
		return serve(r, req)
	}

	assert.Equal(t, http.StatusOK, login().Code)
	assert.Equal(t, http.StatusOK, login().Code)

	rec := login()
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
	assert.Equal(t, "10", rec.Header().Get("Retry-After"), "six logins per minute means one token every ten seconds")
	env := decodeEnvelope(t, rec)
	require.NotNil(t, env.Error)
	assert.Equal(t, apperror.CodeTooManyRequests, env.Error.Code)
	assert.Equal(t, "too many login attempts, please try again later", env.Error.Message)

	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code, "the global bucket of the same client is unaffected")
	assert.ElementsMatch(t, []string{"10.0.0.1", loginKeyPrefix + "10.0.0.1"}, l.entryKeys())
}

func TestMiddleware_ConcurrentRequestsFromOneIP(t *testing.T) {
	t.Parallel()
	const (
		goroutines   = 50
		perGoroutine = 10
		burst        = 120
	)
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: burst})
	r, hits := countingRouter(l.Middleware())

	var allowed, denied, other atomic.Int64
	var wg sync.WaitGroup
	for range goroutines {
		wg.Go(func() {
			for range perGoroutine {
				switch getFrom(t, r, "10.0.0.9").Code {
				case http.StatusOK:
					allowed.Add(1)
				case http.StatusTooManyRequests:
					denied.Add(1)
				default:
					other.Add(1)
				}
			}
		})
	}
	wg.Wait()

	assert.Equal(t, int64(burst), allowed.Load(), "exactly the burst is allowed when the rate is zero")
	assert.Equal(t, int64(goroutines*perGoroutine-burst), denied.Load())
	assert.Zero(t, other.Load())
	assert.Equal(t, int64(burst), hits.Load())
	assert.Len(t, l.entryKeys(), 1)
}

func TestMiddleware_ConcurrentRequestsFromManyIPs(t *testing.T) {
	t.Parallel()
	const (
		goroutines   = 50
		perGoroutine = 5
	)
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: perGoroutine})
	r, hits := countingRouter(l.Middleware())

	var allowed atomic.Int64
	var wg sync.WaitGroup
	for i := range goroutines {
		ip := "10.1.0." + strconv.Itoa(i+1)
		wg.Go(func() {
			for range perGoroutine {
				if getFrom(t, r, ip).Code == http.StatusOK {
					allowed.Add(1)
				}
			}
		})
	}
	wg.Wait()

	assert.Equal(t, int64(goroutines*perGoroutine), allowed.Load(), "every client stays within its own burst")
	assert.Equal(t, int64(goroutines*perGoroutine), hits.Load())
	assert.Len(t, l.entryKeys(), goroutines)
}

func TestEvictIdle_RemovesOnlyEntriesIdleLongerThanTTL(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(testConfig())
	now := time.Now()
	l.limiter("stale", 1, 1, now.Add(-idleTTL-time.Second))
	l.limiter("boundary", 1, 1, now.Add(-idleTTL))
	l.limiter("fresh", 1, 1, now.Add(-time.Minute))

	assert.Equal(t, 1, l.evictIdle(now))
	assert.ElementsMatch(t, []string{"boundary", "fresh"}, l.entryKeys())

	assert.Equal(t, 0, l.evictIdle(now), "a second pass finds nothing new")
}

func TestLimiter_RefreshesLastSeenOnEveryUse(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(testConfig())
	first := time.Now()
	created := l.limiter("k", 1, 1, first)

	later := first.Add(2 * idleTTL)
	reused := l.limiter("k", 1, 1, later)

	assert.Same(t, created, reused, "the bucket survives as long as it is used")
	assert.Equal(t, 0, l.evictIdle(later.Add(idleTTL)), "idle for exactly the TTL is not idle for longer")
	assert.Equal(t, 1, l.evictIdle(later.Add(idleTTL+time.Nanosecond)))
}

func TestMiddleware_EvictedClientStartsWithAFullBurst(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(RateLimitConfig{RPS: 0, Burst: 1})
	r, _ := countingRouter(l.Middleware())

	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code)
	assert.Equal(t, http.StatusTooManyRequests, getFrom(t, r, "10.0.0.1").Code)

	require.Equal(t, 1, l.evictIdle(time.Now().Add(idleTTL+time.Second)))
	assert.Equal(t, http.StatusOK, getFrom(t, r, "10.0.0.1").Code)
}

func TestJanitor_EvictsIdleEntriesPeriodically(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(testConfig())
	l.janitorInterval = time.Millisecond
	l.idleTTL = 0
	l.limiter("10.0.0.1", 1, 1, time.Now().Add(-time.Second))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	l.Start(ctx)

	require.Eventually(t, func() bool { return len(l.entryKeys()) == 0 }, 5*time.Second, time.Millisecond)
}

func TestJanitor_StopsWhenContextIsDone(t *testing.T) {
	t.Parallel()
	l := NewIPRateLimiter(testConfig())
	l.janitorInterval = time.Hour
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	done := make(chan struct{})
	go func() {
		l.janitor(ctx)
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("janitor did not stop after its context was canceled")
	}
}

func TestReserve(t *testing.T) {
	t.Parallel()

	t.Run("takes a token while one is available", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		lim := rate.NewLimiter(1, 1)

		ok, wait := reserve(lim, now)

		assert.True(t, ok)
		assert.Zero(t, wait)
	})

	t.Run("reports the wait without consuming anything", func(t *testing.T) {
		t.Parallel()
		now := time.Now()
		lim := rate.NewLimiter(1, 1)
		_, _ = reserve(lim, now)

		ok, wait := reserve(lim, now)
		require.False(t, ok)
		assert.Equal(t, time.Second, wait)

		ok, _ = reserve(lim, now.Add(time.Second))
		assert.True(t, ok, "the token replenished after one second is still available")
	})

	t.Run("never succeeds with a zero burst", func(t *testing.T) {
		t.Parallel()
		lim := rate.NewLimiter(1, 0)

		ok, wait := reserve(lim, time.Now())

		assert.False(t, ok)
		assert.Equal(t, time.Second, wait)
	})
}

func TestRetryAfterSeconds(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		wait time.Duration
		want int
	}{
		{"zero is at least one second", 0, 1},
		{"a millisecond rounds up to one", time.Millisecond, 1},
		{"a whole second stays one", time.Second, 1},
		{"just over a second rounds up to two", time.Second + time.Millisecond, 2},
		{"two and a half seconds round up to three", 2500 * time.Millisecond, 3},
		{"an endless wait is capped at an hour", time.Duration(math.MaxInt64), maxRetryAfterSeconds},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, retryAfterSeconds(tt.wait))
		})
	}
}
