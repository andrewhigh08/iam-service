package middleware

import (
	"context"
	"math"
	"net/netip"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/response"
)

const (
	janitorInterval = time.Minute
	idleTTL         = 3 * time.Minute
	loginKeyPrefix  = "login:"
	// maxEntries bounds the number of client buckets kept in memory.
	maxEntries = 100_000
	// ipv6ClientBits is the prefix length that identifies one IPv6 client: a subscriber
	// typically controls at least a /64, so single addresses would be free to rotate.
	ipv6ClientBits = 64
	// maxRetryAfterSeconds caps the Retry-After header; a limiter that never refills (a zero
	// rate) would otherwise report an infinite wait.
	maxRetryAfterSeconds = 3600
)

// RateLimitConfig sets the per-IP limits. RPS and Burst apply to every request, LoginPerMinute
// and LoginBurst to the login-like endpoints. A zero rate denies requests once the burst is spent.
type RateLimitConfig struct {
	RPS            float64
	Burst          int
	LoginPerMinute int
	LoginBurst     int
}

// entry is the limiter of one key and when it was last used.
type entry struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// IPRateLimiter keeps an in-memory token bucket per client. Clients are keyed by IPv4 address
// or IPv6 /64 prefix. Entries idle for more than three minutes are evicted by the janitor
// started with Start, and the table never grows beyond maxEntries: at the cap an arbitrary
// entry makes room for a new client.
type IPRateLimiter struct {
	cfg             RateLimitConfig
	janitorInterval time.Duration
	idleTTL         time.Duration
	maxEntries      int
	mu              sync.Mutex
	entries         map[string]*entry
}

// NewIPRateLimiter creates a limiter with cfg; call Start to run its janitor.
func NewIPRateLimiter(cfg RateLimitConfig) *IPRateLimiter {
	return &IPRateLimiter{
		cfg:             cfg,
		janitorInterval: janitorInterval,
		idleTTL:         idleTTL,
		maxEntries:      maxEntries,
		entries:         make(map[string]*entry),
	}
}

// Start runs the janitor goroutine until ctx is done.
func (l *IPRateLimiter) Start(ctx context.Context) {
	go l.janitor(ctx)
}

// Middleware enforces the global per-client limit and answers 429 with Retry-After when exceeded.
func (l *IPRateLimiter) Middleware() gin.HandlerFunc {
	limit := rate.Limit(l.cfg.RPS)
	return func(c *gin.Context) {
		l.limitRequest(c, clientKey(c.ClientIP()), limit, l.cfg.Burst, "rate limit exceeded")
	}
}

// LoginMiddleware enforces the stricter per-client login limit, tracked separately from the global one.
func (l *IPRateLimiter) LoginMiddleware() gin.HandlerFunc {
	limit := rate.Limit(float64(l.cfg.LoginPerMinute) / 60)
	return func(c *gin.Context) {
		l.limitRequest(c, loginKeyPrefix+clientKey(c.ClientIP()), limit, l.cfg.LoginBurst, "too many login attempts, please try again later")
	}
}

// limitRequest lets the request through or aborts it with 429 and message.
func (l *IPRateLimiter) limitRequest(c *gin.Context, key string, limit rate.Limit, burst int, message string) {
	now := time.Now()
	ok, wait := reserve(l.limiter(key, limit, burst, now), now)
	if !ok {
		response.TooManyRequests(c, message, retryAfterSeconds(wait))
		c.Abort()
		return
	}
	c.Next()
}

// limiter returns the limiter stored under key, creating it when absent, and marks it as used at now.
func (l *IPRateLimiter) limiter(key string, limit rate.Limit, burst int, now time.Time) *rate.Limiter {
	l.mu.Lock()
	defer l.mu.Unlock()

	e, ok := l.entries[key]
	if !ok {
		if len(l.entries) >= l.maxEntries {
			l.evictOne()
		}
		e = &entry{limiter: rate.NewLimiter(limit, burst)}
		l.entries[key] = e
	}
	e.lastSeen = now
	return e.limiter
}

// evictOne removes an arbitrary entry; the caller holds the lock. Map iteration order is
// random, so under a flood of new clients the flood mostly evicts itself.
func (l *IPRateLimiter) evictOne() {
	for key := range l.entries {
		delete(l.entries, key)
		return
	}
}

// janitor evicts idle entries every janitorInterval until ctx is done.
func (l *IPRateLimiter) janitor(ctx context.Context) {
	ticker := time.NewTicker(l.janitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			l.evictIdle(now)
		}
	}
}

// evictIdle removes entries unused for longer than idleTTL as of now and returns how many were removed.
func (l *IPRateLimiter) evictIdle(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	removed := 0
	for key, e := range l.entries {
		if now.Sub(e.lastSeen) > l.idleTTL {
			delete(l.entries, key)
			removed++
		}
	}
	return removed
}

// clientKey normalizes a client IP into a bucket key: the address itself for IPv4 (including
// IPv4-mapped IPv6), the /64 prefix for IPv6. A value that is not an IP is used as it is.
func clientKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	addr = addr.Unmap().WithZone("")
	if !addr.Is6() {
		return addr.String()
	}
	prefix, err := addr.Prefix(ipv6ClientBits)
	if err != nil {
		return addr.String()
	}
	return prefix.String()
}

// reserve takes one token from lim when one is available at now. Otherwise it reports false
// together with the time until a token becomes available, without consuming anything.
func reserve(lim *rate.Limiter, now time.Time) (bool, time.Duration) {
	r := lim.ReserveN(now, 1)
	if !r.OK() {
		return false, time.Second
	}
	delay := r.DelayFrom(now)
	if delay <= 0 {
		return true, 0
	}
	r.CancelAt(now)
	return false, delay
}

// retryAfterSeconds rounds wait up to whole seconds, never below one and never above an hour.
func retryAfterSeconds(wait time.Duration) int {
	seconds := math.Ceil(wait.Seconds())
	if seconds > maxRetryAfterSeconds {
		return maxRetryAfterSeconds
	}
	return max(1, int(seconds))
}
