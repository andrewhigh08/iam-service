// Package integration holds the HTTP-level tests of the service. They boot the application
// against PostgreSQL and Redis containers started with testcontainers, so Docker is required.
package integration

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// Images and credentials of the containers used by the tests.
const (
	postgresImage    = "postgres:17-alpine"
	redisImage       = "redis:8-alpine"
	postgresUser     = "iam_user"
	postgresPassword = "iam_password"
	postgresDB       = "iam_test_db"

	postgresPort   = "5432/tcp"
	redisPort      = "6379/tcp"
	startupTimeout = 2 * time.Minute
)

// endpoint is the host and mapped port under which a container is reachable from the tests.
type endpoint struct {
	Host string
	Port string
}

// testContainers is one PostgreSQL and one Redis container shared by the test package.
type testContainers struct {
	Postgres     testcontainers.Container
	Redis        testcontainers.Container
	PostgresAddr endpoint
	RedisAddr    endpoint
}

// startContainers launches PostgreSQL and Redis and waits until both accept connections.
// Whatever was started before a failure is terminated.
func startContainers(ctx context.Context) (*testContainers, error) {
	c := &testContainers{}
	var err error
	if c.Postgres, c.PostgresAddr, err = startPostgres(ctx); err != nil {
		return nil, err
	}
	if c.Redis, c.RedisAddr, err = startRedis(ctx); err != nil {
		return nil, errors.Join(err, c.Terminate(ctx))
	}
	return c, nil
}

// Terminate stops both containers.
func (c *testContainers) Terminate(ctx context.Context) error {
	return errors.Join(terminate(ctx, c.Redis), terminate(ctx, c.Postgres))
}

func startPostgres(ctx context.Context) (testcontainers.Container, endpoint, error) {
	container, err := testcontainers.Run(ctx, postgresImage,
		testcontainers.WithExposedPorts(postgresPort),
		testcontainers.WithEnv(map[string]string{
			"POSTGRES_USER":     postgresUser,
			"POSTGRES_PASSWORD": postgresPassword,
			"POSTGRES_DB":       postgresDB,
		}),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(startupTimeout),
			wait.ForListeningPort(postgresPort).WithStartupTimeout(startupTimeout),
		),
	)
	return started(ctx, container, postgresPort, err)
}

func startRedis(ctx context.Context) (testcontainers.Container, endpoint, error) {
	container, err := testcontainers.Run(ctx, redisImage,
		testcontainers.WithExposedPorts(redisPort),
		testcontainers.WithWaitStrategy(wait.ForListeningPort(redisPort).WithStartupTimeout(startupTimeout)),
	)
	return started(ctx, container, redisPort, err)
}

// started resolves the endpoint of a container that Run returned, terminating it when the
// start or the lookup failed.
func started(ctx context.Context, container testcontainers.Container, port string, err error) (testcontainers.Container, endpoint, error) {
	if err != nil {
		return nil, endpoint{}, errors.Join(fmt.Errorf("start container: %w", err), terminate(ctx, container))
	}
	host, err := container.Host(ctx)
	if err != nil {
		return nil, endpoint{}, errors.Join(fmt.Errorf("container host: %w", err), terminate(ctx, container))
	}
	mapped, err := container.MappedPort(ctx, port)
	if err != nil {
		return nil, endpoint{}, errors.Join(fmt.Errorf("container port: %w", err), terminate(ctx, container))
	}
	return container, endpoint{Host: host, Port: mapped.Port()}, nil
}

// terminate stops a container, tolerating one that was never started.
func terminate(ctx context.Context, container testcontainers.Container) error {
	if container == nil {
		return nil
	}
	return container.Terminate(ctx)
}
