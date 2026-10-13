// Package app wires the IAM service together: it opens the database and Redis connections,
// applies migrations, builds the services and the HTTP router, seeds the default data and
// runs the HTTP server until it is asked to shut down.
package app

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/casbin/casbin/v3/persist"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/adapter/http/middleware"
	"github.com/andrewhigh08/iam-service/internal/config"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/telemetry"
)

// Timeouts that are not part of the configuration.
const (
	pingTimeout         = 5 * time.Second
	idleTimeout         = 60 * time.Second
	defaultCloseTimeout = 10 * time.Second
)

// App is a fully wired instance of the service. Build it with New, serve it with Run or
// through Handler, and release it with Close.
type App struct {
	cfg     *config.Config
	base    *logger.Logger // logger handed to every component
	log     *logger.Logger // base tagged with the app component
	version string

	tracer  *telemetry.Provider
	db      *gorm.DB
	sqlDB   *sql.DB
	rdb     *redis.Client
	watcher persist.Watcher
	limiter *middleware.IPRateLimiter
	router  *gin.Engine
	srv     *http.Server

	closeOnce sync.Once
	closeErr  error
}

// New builds the application from cfg: it initializes tracing, connects to PostgreSQL and
// Redis, applies the embedded migrations when DB_MIGRATE is set, loads or generates the
// signing keys, seeds the default policies and administrator and prepares the HTTP router.
// Resources opened before a failure are released. version is reported by the liveness probe
// and attached to traces; a nil log means a default JSON logger.
func New(ctx context.Context, cfg *config.Config, log *logger.Logger, version string) (*App, error) {
	if cfg == nil {
		return nil, errors.New("app: configuration is required")
	}
	if log == nil {
		log = logger.New(logger.DefaultConfig())
	}
	a := &App{cfg: cfg, base: log, log: log.WithComponent("app"), version: version}
	if err := a.init(ctx); err != nil {
		return nil, errors.Join(err, a.Close())
	}
	return a, nil
}

// init runs the wiring steps of New in dependency order.
func (a *App) init(ctx context.Context) error {
	if err := a.initTelemetry(ctx); err != nil {
		return err
	}
	if err := a.openDatabase(ctx); err != nil {
		return err
	}
	if err := a.openRedis(ctx); err != nil {
		return err
	}
	svcs, err := a.buildServices(ctx)
	if err != nil {
		return err
	}

	a.limiter = middleware.NewIPRateLimiter(middleware.RateLimitConfig(a.cfg.RateLimit))
	router, err := a.newRouter(svcs)
	if err != nil {
		return err
	}
	a.router = router
	a.srv = &http.Server{
		Addr:              ":" + a.cfg.Server.Port,
		Handler:           router,
		ReadTimeout:       a.cfg.Server.ReadTimeout,
		ReadHeaderTimeout: a.cfg.Server.ReadTimeout,
		WriteTimeout:      a.cfg.Server.WriteTimeout,
		IdleTimeout:       idleTimeout,
	}
	return nil
}

// initTelemetry installs the global tracer provider when OTEL_ENABLED is set.
func (a *App) initTelemetry(ctx context.Context) error {
	tracer, err := telemetry.Init(ctx, telemetry.Config{
		Enabled:        a.cfg.Telemetry.Enabled,
		Endpoint:       a.cfg.Telemetry.Endpoint,
		ServiceName:    a.cfg.Telemetry.ServiceName,
		ServiceVersion: a.version,
		Environment:    a.cfg.Telemetry.Environment,
	})
	if err != nil {
		return fmt.Errorf("init telemetry: %w", err)
	}
	a.tracer = tracer
	return nil
}

// buildServices creates the enforcer and the services on top of the open connections and
// seeds the default data.
func (a *App) buildServices(ctx context.Context) (*services, error) {
	enforcer, err := a.newEnforcer()
	if err != nil {
		return nil, err
	}
	svcs, err := a.newServices(enforcer)
	if err != nil {
		return nil, err
	}
	if err := a.seed(ctx, svcs); err != nil {
		return nil, err
	}
	return svcs, nil
}

// Handler returns the HTTP handler of the application, for tests that serve it without Run.
func (a *App) Handler() http.Handler {
	return a.router
}

// Close releases every resource the application holds, without touching the HTTP server:
// the policy watcher, the tracer, the Redis client and the database pool. It is idempotent;
// Run calls it once the server has shut down.
func (a *App) Close() error {
	a.closeOnce.Do(func() { a.closeErr = a.release() })
	return a.closeErr
}

// release closes the resources in reverse order of creation and joins their errors.
func (a *App) release() error {
	ctx, cancel := context.WithTimeout(context.Background(), a.closeTimeout())
	defer cancel()

	var errs []error
	if a.watcher != nil {
		a.watcher.Close()
	}
	if err := a.tracer.Shutdown(ctx); err != nil {
		errs = append(errs, fmt.Errorf("shutdown telemetry: %w", err))
	}
	if a.rdb != nil {
		if err := a.rdb.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close redis: %w", err))
		}
	}
	if a.sqlDB != nil {
		if err := a.sqlDB.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close database: %w", err))
		}
	}
	return errors.Join(errs...)
}

// closeTimeout is the time allowed for shutting down the server and flushing traces.
func (a *App) closeTimeout() time.Duration {
	if a.cfg.Server.ShutdownTimeout > 0 {
		return a.cfg.Server.ShutdownTimeout
	}
	return defaultCloseTimeout
}
