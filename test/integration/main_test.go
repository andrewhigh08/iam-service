package integration

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/andrewhigh08/iam-service/internal/app"
	"github.com/andrewhigh08/iam-service/internal/config"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Values the suite boots the service with; the tests rely on them directly.
const (
	adminEmail         = "admin@example.com"
	adminPassword      = "Admin123!"
	appVersion         = "integration-test"
	tokenIssuer        = "iam-service"
	accessTTL          = 15 * time.Minute
	refreshTTL         = 168 * time.Hour
	sessionMaxAge      = 720 * time.Hour
	lockoutMaxAttempts = 3
	casbinModelPath    = "../../configs/casbin_model.conf"

	setupTimeout    = 3 * time.Minute
	teardownTimeout = 30 * time.Second
)

// suite is the environment every test of the package shares: the containers, the booted
// application and the HTTP server in front of it. TestMain builds it once; tests only read it.
type suite struct {
	containers *testContainers
	cfg        *config.Config
	app        *app.App
	server     *httptest.Server
	keysDir    string
}

// shared is assigned once by TestMain before any test runs and stays nil under -short.
var shared *suite

func TestMain(m *testing.M) {
	flag.Parse()
	if testing.Short() {
		os.Exit(m.Run())
	}
	code, err := run(m)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration suite:", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func run(m *testing.M) (int, error) {
	s, err := startSuite()
	if err != nil {
		return 0, err
	}
	defer s.stop()
	shared = s
	return m.Run(), nil
}

func env(t *testing.T) *suite {
	t.Helper()
	if shared == nil {
		t.Skip("integration tests need Docker and are skipped under -short")
	}
	return shared
}

func startSuite() (*suite, error) {
	ctx, cancel := context.WithTimeout(context.Background(), setupTimeout)
	defer cancel()

	containers, err := startContainers(ctx)
	if err != nil {
		return nil, fmt.Errorf("start containers: %w", err)
	}
	s := &suite{containers: containers}
	if err = s.boot(ctx); err != nil {
		s.stop()
		return nil, err
	}
	return s, nil
}

func (s *suite) boot(ctx context.Context) error {
	keysDir, err := os.MkdirTemp("", "iam-integration-keys-")
	if err != nil {
		return fmt.Errorf("create key directory: %w", err)
	}
	s.keysDir = keysDir

	port, err := freePort()
	if err != nil {
		return fmt.Errorf("pick a server port: %w", err)
	}
	s.cfg = newConfig(s.containers, keysDir, port)
	if err = s.cfg.Validate(); err != nil {
		return fmt.Errorf("invalid test configuration: %w", err)
	}

	application, err := app.New(ctx, s.cfg, newLogger(), appVersion)
	if err != nil {
		return fmt.Errorf("boot application: %w", err)
	}
	s.app = application
	s.server = httptest.NewServer(application.Handler())
	return nil
}

// stop releases the suite in reverse order of creation; it tolerates a partially built one.
func (s *suite) stop() {
	if s.server != nil {
		s.server.Close()
	}
	if s.app != nil {
		if err := s.app.Close(); err != nil {
			fmt.Fprintln(os.Stderr, "integration suite: close application:", err)
		}
	}
	if s.keysDir != "" {
		_ = os.RemoveAll(s.keysDir)
	}
	ctx, cancel := context.WithTimeout(context.Background(), teardownTimeout)
	defer cancel()
	if err := s.containers.Terminate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "integration suite: terminate containers:", err)
	}
}

func (s *suite) dsnFor(name string) string {
	u := url.URL{
		Scheme:   "postgres",
		User:     url.UserPassword(postgresUser, postgresPassword),
		Host:     net.JoinHostPort(s.containers.PostgresAddr.Host, s.containers.PostgresAddr.Port),
		Path:     "/" + name,
		RawQuery: "sslmode=disable",
	}
	return u.String()
}

// newConfig builds the configuration of the application under test: what the environment
// variables of a deployment would produce, with generous rate limits so the suite is never
// throttled and a low lockout threshold so the lockout test stays cheap. Tracing is off.
func newConfig(c *testContainers, keysDir, port string) *config.Config {
	return &config.Config{
		Server: config.ServerConfig{
			Port:            port,
			ReadTimeout:     15 * time.Second,
			WriteTimeout:    15 * time.Second,
			ShutdownTimeout: 5 * time.Second,
		},
		Log: config.LogConfig{Level: "info", Format: "json"},
		Database: config.DatabaseConfig{
			Host:         c.PostgresAddr.Host,
			Port:         c.PostgresAddr.Port,
			User:         postgresUser,
			Password:     postgresPassword,
			Name:         postgresDB,
			SSLMode:      "disable",
			MaxOpenConns: 25,
			MaxIdleConns: 5,
			Migrate:      true,
		},
		Redis: config.RedisConfig{Host: c.RedisAddr.Host, Port: c.RedisAddr.Port},
		JWT: config.JWTConfig{
			PrivateKeyPath:  filepath.Join(keysDir, "private.pem"),
			PublicKeyPath:   filepath.Join(keysDir, "public.pem"),
			AccessTokenTTL:  accessTTL,
			RefreshTokenTTL: refreshTTL,
			SessionMaxAge:   sessionMaxAge,
			Issuer:          tokenIssuer,
		},
		Admin:     config.AdminConfig{Email: adminEmail, Password: adminPassword},
		Casbin:    config.CasbinConfig{ModelPath: casbinModelPath},
		Lockout:   config.LockoutConfig{MaxAttempts: lockoutMaxAttempts, Duration: 15 * time.Minute},
		Password:  config.PasswordConfig{MaxAge: 2160 * time.Hour},
		RateLimit: config.RateLimitConfig{RPS: 1000, Burst: 1000, LoginPerMinute: 100, LoginBurst: 100},
		Telemetry: config.TelemetryConfig{Enabled: false, ServiceName: "iam-service"},
		DevMode:   true,
	}
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}

// newLogger returns the application logger: silent unless the tests run with -v.
func newLogger() *logger.Logger {
	cfg := logger.Config{Level: "info", Format: "text", Output: io.Discard}
	if testing.Verbose() {
		cfg.Output = os.Stderr
	}
	return logger.New(cfg)
}
