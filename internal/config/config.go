// Package config loads the service configuration from environment variables.
//
// When a .env file exists in the working directory it is read first, without overriding
// variables already present in the environment. The result is checked by Validate.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/ilyakaznacheev/cleanenv"
	"github.com/joho/godotenv"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
)

const (
	// DevModeAdminPassword is the administrator password used in DEV_MODE when ADMIN_PASSWORD is empty.
	DevModeAdminPassword = "Admin123!"
	// dbConnectTimeout bounds every dial to PostgreSQL, including pool refills at runtime.
	dbConnectTimeout = 5 * time.Second
)

// Config holds the complete service configuration.
type Config struct {
	Server    ServerConfig
	Log       LogConfig
	Database  DatabaseConfig
	Redis     RedisConfig
	JWT       JWTConfig
	Admin     AdminConfig
	Casbin    CasbinConfig
	Lockout   LockoutConfig
	Password  PasswordConfig
	RateLimit RateLimitConfig
	CORS      CORSConfig
	Telemetry TelemetryConfig
	// DevMode generates RSA keys when they are missing and allows the default admin password.
	DevMode bool `env:"DEV_MODE" env-default:"false"`
}

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	Port            string        `env:"SERVER_PORT" env-default:"8080"`
	ReadTimeout     time.Duration `env:"SERVER_READ_TIMEOUT" env-default:"15s"`
	WriteTimeout    time.Duration `env:"SERVER_WRITE_TIMEOUT" env-default:"15s"`
	ShutdownTimeout time.Duration `env:"SERVER_SHUTDOWN_TIMEOUT" env-default:"10s"`
	// TrustedProxies lists the proxies whose forwarding headers are honored; empty trusts none.
	TrustedProxies []string `env:"TRUSTED_PROXIES" env-default:""`
}

// LogConfig configures the logger.
type LogConfig struct {
	Level  string `env:"LOG_LEVEL" env-default:"info"`
	Format string `env:"LOG_FORMAT" env-default:"json"`
}

// DatabaseConfig configures the PostgreSQL connection. MaxOpenConns is 0 for no limit or at
// least 2: seeding holds a transaction while the policy adapter writes on another connection.
type DatabaseConfig struct {
	Host         string `env:"DB_HOST" env-default:"localhost"`
	Port         string `env:"DB_PORT" env-default:"5432"`
	User         string `env:"DB_USER" env-default:"iam_user"`
	Password     string `env:"DB_PASSWORD" env-default:"iam_password"`
	Name         string `env:"DB_NAME" env-default:"iam_db"`
	SSLMode      string `env:"DB_SSLMODE" env-default:"disable"`
	MaxOpenConns int    `env:"DB_MAX_OPEN_CONNS" env-default:"25"`
	MaxIdleConns int    `env:"DB_MAX_IDLE_CONNS" env-default:"5"`
	// Migrate applies the embedded migrations at startup.
	Migrate bool `env:"DB_MIGRATE" env-default:"true"`
}

// RedisConfig configures the Redis connection.
type RedisConfig struct {
	Host     string `env:"REDIS_HOST" env-default:"localhost"`
	Port     string `env:"REDIS_PORT" env-default:"6379"`
	Password string `env:"REDIS_PASSWORD" env-default:""`
	DB       int    `env:"REDIS_DB" env-default:"0"`
}

// JWTConfig configures token signing and lifetimes. SessionMaxAge bounds how long a session
// may be kept alive by refreshing; zero removes the bound.
type JWTConfig struct {
	PrivateKeyPath  string        `env:"JWT_PRIVATE_KEY_PATH" env-default:"configs/keys/private.pem"`
	PublicKeyPath   string        `env:"JWT_PUBLIC_KEY_PATH" env-default:"configs/keys/public.pem"`
	AccessTokenTTL  time.Duration `env:"JWT_ACCESS_TOKEN_TTL" env-default:"15m"`
	RefreshTokenTTL time.Duration `env:"JWT_REFRESH_TOKEN_TTL" env-default:"168h"`
	SessionMaxAge   time.Duration `env:"JWT_SESSION_MAX_AGE" env-default:"720h"`
	Issuer          string        `env:"JWT_ISSUER" env-default:"iam-service"`
}

// AdminConfig describes the administrator seeded at startup; an empty Email skips seeding.
type AdminConfig struct {
	Email    string `env:"ADMIN_EMAIL" env-default:"admin@example.com"`
	Password string `env:"ADMIN_PASSWORD" env-default:""`
}

// CasbinConfig configures the authorization enforcer.
type CasbinConfig struct {
	ModelPath string `env:"CASBIN_MODEL_PATH" env-default:"configs/casbin_model.conf"`
	// WatcherEnabled propagates policy changes between replicas through Redis.
	WatcherEnabled bool `env:"AUTHZ_WATCHER_ENABLED" env-default:"false"`
}

// LockoutConfig configures the temporary lockout applied after repeated failed logins.
type LockoutConfig struct {
	MaxAttempts int           `env:"LOCKOUT_MAX_ATTEMPTS" env-default:"5"`
	Duration    time.Duration `env:"LOCKOUT_DURATION" env-default:"15m"`
}

// PasswordConfig configures password aging; a zero MaxAge disables expiry.
type PasswordConfig struct {
	MaxAge time.Duration `env:"PASSWORD_MAX_AGE" env-default:"2160h"`
}

// RateLimitConfig configures the per-IP request limiters.
type RateLimitConfig struct {
	RPS            float64 `env:"RATE_LIMIT_RPS" env-default:"100"`
	Burst          int     `env:"RATE_LIMIT_BURST" env-default:"200"`
	LoginPerMinute int     `env:"LOGIN_RATE_LIMIT_PER_MIN" env-default:"5"`
	LoginBurst     int     `env:"LOGIN_RATE_LIMIT_BURST" env-default:"10"`
}

// CORSConfig configures cross-origin access.
// No origins disables CORS; "*" allows any origin without credentials.
type CORSConfig struct {
	AllowedOrigins []string `env:"CORS_ALLOWED_ORIGINS" env-default:""`
}

// TelemetryConfig configures OpenTelemetry tracing.
type TelemetryConfig struct {
	Enabled     bool   `env:"OTEL_ENABLED" env-default:"false"`
	Endpoint    string `env:"OTEL_ENDPOINT" env-default:"localhost:4317"`
	ServiceName string `env:"OTEL_SERVICE_NAME" env-default:"iam-service"`
	Environment string `env:"OTEL_ENVIRONMENT" env-default:"development"`
}

// Load reads the configuration from a .env file (when present) and the environment, then validates it.
func Load() (*Config, error) {
	if _, err := os.Stat(".env"); err == nil {
		if err := godotenv.Load(); err != nil {
			return nil, fmt.Errorf("load .env: %w", err)
		}
	}

	var cfg Config
	if err := cleanenv.ReadEnv(&cfg); err != nil {
		return nil, fmt.Errorf("read environment: %w", err)
	}
	cfg.normalize()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Validate checks the loaded values and returns every problem found, joined into one error.
// Each message names the environment variable it concerns.
func (c *Config) Validate() error {
	return errors.Join(slices.Concat(
		c.Server.validate(),
		c.Database.validate(),
		c.JWT.validate(),
		c.validateAdmin(),
		c.Lockout.validate(),
		c.Password.validate(),
		c.RateLimit.validate(),
		c.CORS.validate(),
	)...)
}

func (c ServerConfig) validate() []error {
	if port, err := strconv.Atoi(c.Port); err != nil || port < 1 || port > 65535 {
		return []error{fmt.Errorf("SERVER_PORT must be a number between 1 and 65535, got %q", c.Port)}
	}
	return nil
}

func (c DatabaseConfig) validate() []error {
	var errs []error
	if c.MaxOpenConns < 0 || c.MaxOpenConns == 1 {
		errs = append(errs, errors.New("DB_MAX_OPEN_CONNS must be 0 (unlimited) or at least 2: seeding holds a transaction while the policy adapter uses a second connection"))
	}
	if c.MaxIdleConns < 0 {
		errs = append(errs, errors.New("DB_MAX_IDLE_CONNS must not be negative"))
	}
	if c.MaxOpenConns > 0 && c.MaxIdleConns > c.MaxOpenConns {
		errs = append(errs, errors.New("DB_MAX_IDLE_CONNS must not exceed DB_MAX_OPEN_CONNS"))
	}
	return errs
}

func (c JWTConfig) validate() []error {
	var errs []error
	if c.AccessTokenTTL <= 0 {
		errs = append(errs, errors.New("JWT_ACCESS_TOKEN_TTL must be greater than zero"))
	}
	if c.RefreshTokenTTL <= 0 {
		errs = append(errs, errors.New("JWT_REFRESH_TOKEN_TTL must be greater than zero"))
	}
	if c.SessionMaxAge < 0 {
		errs = append(errs, errors.New("JWT_SESSION_MAX_AGE must not be negative; 0 disables the bound"))
	}
	if c.PrivateKeyPath == "" {
		errs = append(errs, errors.New("JWT_PRIVATE_KEY_PATH must not be empty"))
	}
	if c.PublicKeyPath == "" {
		errs = append(errs, errors.New("JWT_PUBLIC_KEY_PATH must not be empty"))
	}
	return errs
}

// validateAdmin requires a policy-compliant administrator password outside DEV_MODE whenever
// seeding is enabled; the one privileged account must not be weaker than every other one.
func (c *Config) validateAdmin() []error {
	if c.DevMode || c.Admin.Email == "" {
		return nil
	}
	if c.Admin.Password == "" {
		return []error{errors.New("ADMIN_PASSWORD is required when DEV_MODE is false; set ADMIN_EMAIL empty to skip seeding")}
	}
	if err := validator.ValidatePassword(c.Admin.Password, validator.DefaultPolicy()); err != nil {
		return []error{fmt.Errorf("ADMIN_PASSWORD does not meet the password policy: %s", policyViolations(err))}
	}
	return nil
}

// policyViolations renders the rules a password violated, as listed by validator.ValidatePassword.
func policyViolations(err error) string {
	if appErr, ok := apperror.AsAppError(err); ok {
		if violations, ok := appErr.Details["errors"].([]string); ok {
			return strings.Join(violations, "; ")
		}
	}
	return err.Error()
}

func (c LockoutConfig) validate() []error {
	var errs []error
	if c.MaxAttempts < 1 {
		errs = append(errs, errors.New("LOCKOUT_MAX_ATTEMPTS must be at least 1"))
	}
	if c.Duration <= 0 {
		errs = append(errs, errors.New("LOCKOUT_DURATION must be greater than zero"))
	}
	return errs
}

func (c PasswordConfig) validate() []error {
	if c.MaxAge < 0 {
		return []error{errors.New("PASSWORD_MAX_AGE must not be negative; 0 disables expiry")}
	}
	return nil
}

func (c RateLimitConfig) validate() []error {
	var errs []error
	if c.RPS <= 0 {
		errs = append(errs, errors.New("RATE_LIMIT_RPS must be greater than zero"))
	}
	if c.Burst < 1 {
		errs = append(errs, errors.New("RATE_LIMIT_BURST must be at least 1"))
	}
	if c.LoginPerMinute <= 0 {
		errs = append(errs, errors.New("LOGIN_RATE_LIMIT_PER_MIN must be greater than zero"))
	}
	if c.LoginBurst < 1 {
		errs = append(errs, errors.New("LOGIN_RATE_LIMIT_BURST must be at least 1"))
	}
	return errs
}

func (c CORSConfig) validate() []error {
	var errs []error
	for _, origin := range c.AllowedOrigins {
		switch {
		case origin == "*":
		case !strings.HasPrefix(origin, "http://") && !strings.HasPrefix(origin, "https://"):
			errs = append(errs, fmt.Errorf("CORS_ALLOWED_ORIGINS entry %q must start with http:// or https://", origin))
		case strings.Count(origin, "*") > 1:
			errs = append(errs, fmt.Errorf("CORS_ALLOWED_ORIGINS entry %q may contain at most one wildcard", origin))
		}
	}
	return errs
}

// DSN returns the PostgreSQL connection string in libpq keyword/value form. Every value is
// quoted, so empty values and values with spaces, quotes or backslashes are passed intact, and
// every dial is bounded by connect_timeout.
func (c *Config) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s connect_timeout=%d",
		dsnValue(c.Database.Host), dsnValue(c.Database.Port), dsnValue(c.Database.User), dsnValue(c.Database.Password),
		dsnValue(c.Database.Name), dsnValue(c.Database.SSLMode), int(dbConnectTimeout/time.Second))
}

// dsnEscaper escapes the two characters that are special inside a quoted libpq value.
var dsnEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

// dsnValue quotes v as a libpq keyword/value string.
func dsnValue(v string) string {
	return "'" + dsnEscaper.Replace(v) + "'"
}

// RedisAddr returns the host:port address of the Redis server.
func (c *Config) RedisAddr() string {
	return net.JoinHostPort(c.Redis.Host, c.Redis.Port)
}

// normalize trims list entries and applies the DEV_MODE admin password fallback.
func (c *Config) normalize() {
	c.Server.TrustedProxies = cleanList(c.Server.TrustedProxies)
	c.CORS.AllowedOrigins = cleanList(c.CORS.AllowedOrigins)
	c.Admin.Email = strings.ToLower(strings.TrimSpace(c.Admin.Email))
	if c.DevMode && c.Admin.Password == "" {
		c.Admin.Password = DevModeAdminPassword
	}
}

// cleanList trims every entry and drops the empty ones.
func cleanList(in []string) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out
}
