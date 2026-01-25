package integration

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"
)

// TestContainers holds references to test containers
type TestContainers struct {
	PostgresContainer testcontainers.Container
	RedisContainer    testcontainers.Container
	DB                *gorm.DB
	Redis             *redis.Client
}

// SetupTestContainers starts PostgreSQL and Redis containers for integration testing
func SetupTestContainers(ctx context.Context) (*TestContainers, error) {
	tc := &TestContainers{}

	// Start PostgreSQL container
	pgContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "postgres:16-alpine",
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_DB":       "iam_test_db",
				"POSTGRES_USER":     "iam_user",
				"POSTGRES_PASSWORD": "iam_password",
			},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start postgres container: %w", err)
	}
	tc.PostgresContainer = pgContainer

	// Get PostgreSQL connection details
	pgHost, err := pgContainer.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get postgres host: %w", err)
	}
	pgPort, err := pgContainer.MappedPort(ctx, "5432")
	if err != nil {
		return nil, fmt.Errorf("failed to get postgres port: %w", err)
	}

	// Connect to PostgreSQL
	dsn := fmt.Sprintf("host=%s port=%s user=iam_user password=iam_password dbname=iam_test_db sslmode=disable", pgHost, pgPort.Port())
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Silent),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to postgres: %w", err)
	}
	tc.DB = db

	// Start Redis container
	redisContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        "redis:7-alpine",
			ExposedPorts: []string{"6379/tcp"},
			WaitingFor:   wait.ForLog("Ready to accept connections").WithStartupTimeout(30 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to start redis container: %w", err)
	}
	tc.RedisContainer = redisContainer

	// Get Redis connection details
	redisHost, err := redisContainer.Host(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get redis host: %w", err)
	}
	redisPort, err := redisContainer.MappedPort(ctx, "6379")
	if err != nil {
		return nil, fmt.Errorf("failed to get redis port: %w", err)
	}

	// Connect to Redis
	tc.Redis = redis.NewClient(&redis.Options{
		Addr: fmt.Sprintf("%s:%s", redisHost, redisPort.Port()),
	})

	// Verify Redis connection
	if err := tc.Redis.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("failed to connect to redis: %w", err)
	}

	return tc, nil
}

// Teardown stops and removes all containers
func (tc *TestContainers) Teardown(ctx context.Context) error {
	var errs []error

	if tc.Redis != nil {
		if err := tc.Redis.Close(); err != nil {
			errs = append(errs, fmt.Errorf("failed to close redis client: %w", err))
		}
	}

	if tc.DB != nil {
		if sqlDB, err := tc.DB.DB(); err == nil {
			sqlDB.Close()
		}
	}

	if tc.PostgresContainer != nil {
		if err := tc.PostgresContainer.Terminate(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to terminate postgres container: %w", err))
		}
	}

	if tc.RedisContainer != nil {
		if err := tc.RedisContainer.Terminate(ctx); err != nil {
			errs = append(errs, fmt.Errorf("failed to terminate redis container: %w", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("teardown errors: %v", errs)
	}

	return nil
}

// RunMigrations runs database migrations for testing
func (tc *TestContainers) RunMigrations() error {
	// Create users table
	if err := tc.DB.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id BIGSERIAL PRIMARY KEY,
			email VARCHAR(255) NOT NULL UNIQUE,
			password_hash VARCHAR(255) NOT NULL,
			password_type VARCHAR(20) DEFAULT 'permanent',
			password_changed_at TIMESTAMP,
			full_name VARCHAR(255),
			is_blocked BOOLEAN DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL DEFAULT NOW(),
			updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
			deleted_at TIMESTAMP
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	// Create audit_logs table
	if err := tc.DB.Exec(`
		CREATE TABLE IF NOT EXISTS audit_logs (
			id BIGSERIAL PRIMARY KEY,
			user_id BIGINT NOT NULL,
			action VARCHAR(100) NOT NULL,
			resource_type VARCHAR(50),
			resource_id VARCHAR(50),
			details JSONB,
			ip_address INET,
			user_agent TEXT,
			created_at TIMESTAMP NOT NULL DEFAULT NOW()
		)
	`).Error; err != nil {
		return fmt.Errorf("failed to create audit_logs table: %w", err)
	}

	// Create indices
	tc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`)
	tc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at)`)
	tc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_user_id ON audit_logs(user_id)`)
	tc.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit_logs(created_at)`)

	return nil
}

// CleanupData removes all data from tables (for test isolation)
func (tc *TestContainers) CleanupData() error {
	if err := tc.DB.Exec("TRUNCATE TABLE audit_logs CASCADE").Error; err != nil {
		return err
	}
	if err := tc.DB.Exec("TRUNCATE TABLE users CASCADE").Error; err != nil {
		return err
	}
	if err := tc.Redis.FlushDB(context.Background()).Err(); err != nil {
		return err
	}
	return nil
}
