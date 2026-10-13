package app

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/extra/redisotel/v9"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
	"gorm.io/plugin/opentelemetry/tracing"

	postgresrepo "github.com/andrewhigh08/iam-service/internal/adapter/repository/postgres"
	"github.com/andrewhigh08/iam-service/migrations"
)

const (
	connMaxLifetime    = time.Hour
	slowQueryThreshold = 200 * time.Millisecond
)

// openDatabase connects to PostgreSQL, configures the pool, installs tracing when enabled,
// verifies the connection within pingTimeout and applies the embedded migrations when
// DB_MIGRATE is set. GORM logs through the application logger at Warn level with parameters
// redacted; its own unbounded ping is disabled in favor of the explicit one.
func (a *App) openDatabase(ctx context.Context) error {
	gormLog := gormlogger.NewSlogLogger(a.base.WithComponent("gorm").Logger, gormlogger.Config{
		SlowThreshold:             slowQueryThreshold,
		LogLevel:                  gormlogger.Warn,
		IgnoreRecordNotFoundError: true,
		ParameterizedQueries:      true,
	})
	db, err := gorm.Open(postgres.Open(a.cfg.DSN()), &gorm.Config{
		Logger:               gormLog,
		TranslateError:       true,
		PrepareStmt:          false,
		DisableAutomaticPing: true,
	})
	if err != nil {
		closePool(db)
		return fmt.Errorf("open database: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return fmt.Errorf("access database pool: %w", err)
	}
	a.db, a.sqlDB = db, sqlDB
	sqlDB.SetMaxOpenConns(a.cfg.Database.MaxOpenConns)
	sqlDB.SetMaxIdleConns(a.cfg.Database.MaxIdleConns)
	sqlDB.SetConnMaxLifetime(connMaxLifetime)

	if a.cfg.Telemetry.Enabled {
		if err = db.Use(tracing.NewPlugin(tracing.WithoutMetrics())); err != nil {
			return fmt.Errorf("instrument database: %w", err)
		}
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err = sqlDB.PingContext(pingCtx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	a.log.Info("database connection established", "host", a.cfg.Database.Host, "database", a.cfg.Database.Name)

	if !a.cfg.Database.Migrate {
		return nil
	}
	if err = postgresrepo.Migrate(ctx, sqlDB, migrations.FS); err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}
	a.log.Info("database migrations applied")
	return nil
}

// closePool releases the connection pool of a GORM handle whose setup failed, if it got one.
func closePool(db *gorm.DB) {
	if db == nil {
		return
	}
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// openRedis connects to Redis, installs tracing when enabled, verifies the connection and
// checks that the server does not evict keys.
func (a *App) openRedis(ctx context.Context) error {
	rdb := redis.NewClient(&redis.Options{
		Addr:     a.cfg.RedisAddr(),
		Password: a.cfg.Redis.Password,
		DB:       a.cfg.Redis.DB,
	})
	a.rdb = rdb
	if a.cfg.Telemetry.Enabled {
		if err := redisotel.InstrumentTracing(rdb); err != nil {
			return fmt.Errorf("instrument redis: %w", err)
		}
	}
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	a.log.Info("redis connection established", "addr", a.cfg.RedisAddr())
	a.warnOnEviction(pingCtx)
	return nil
}

// warnOnEviction logs an error when Redis is configured to evict keys under memory pressure:
// every key this service writes enforces a revocation, a session or a lockout, and an evicted
// key fails open. Managed instances often disable CONFIG, in which case nothing is checked.
func (a *App) warnOnEviction(ctx context.Context) {
	values, err := a.rdb.ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		a.log.Debug("redis maxmemory-policy not checked", "error", err)
		return
	}
	policy := values["maxmemory-policy"]
	if strings.HasPrefix(policy, "allkeys-") || strings.HasPrefix(policy, "volatile-") {
		a.log.Error("redis evicts keys under memory pressure, revocations and lockouts can be lost",
			"maxmemory_policy", policy, "required", "noeviction")
	}
}
