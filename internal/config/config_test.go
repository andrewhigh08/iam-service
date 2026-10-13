package config

import (
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// strongPassword satisfies the password policy the administrator password is held to.
const strongPassword = "Str0ng-Secret!"

func envNames(typ reflect.Type) []string {
	var names []string
	for i := range typ.NumField() {
		field := typ.Field(i)
		if name, ok := field.Tag.Lookup("env"); ok {
			names = append(names, name)
			continue
		}
		if field.Type.Kind() == reflect.Struct {
			names = append(names, envNames(field.Type)...)
		}
	}
	return names
}

// unsetEnv removes key for the duration of the test; the original value is restored afterwards.
func unsetEnv(t *testing.T, key string) {
	t.Helper()
	t.Setenv(key, "")
	require.NoError(t, os.Unsetenv(key))
}

// isolate removes every configuration variable from the environment and moves the test into an
// empty temporary directory, so Load sees only what the test sets. Variables exported by a .env
// file during the test are removed again afterwards. It returns the directory.
func isolate(t *testing.T) string {
	t.Helper()
	for _, name := range envNames(reflect.TypeFor[Config]()) {
		unsetEnv(t, name)
	}
	dir := t.TempDir()
	t.Chdir(dir)
	return dir
}

func setenv(t *testing.T, vars map[string]string) {
	t.Helper()
	for key, value := range vars {
		t.Setenv(key, value)
	}
}

func writeDotEnv(t *testing.T, dir, content string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, ".env"), []byte(content), 0o600))
}

func defaultConfig() Config {
	return Config{
		Server: ServerConfig{Port: "8080", ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, ShutdownTimeout: 10 * time.Second},
		Log:    LogConfig{Level: "info", Format: "json"},
		Database: DatabaseConfig{
			Host: "localhost", Port: "5432", User: "iam_user", Password: "iam_password", Name: "iam_db", SSLMode: "disable",
			MaxOpenConns: 25, MaxIdleConns: 5, Migrate: true,
		},
		Redis: RedisConfig{Host: "localhost", Port: "6379"},
		JWT: JWTConfig{
			PrivateKeyPath: "configs/keys/private.pem", PublicKeyPath: "configs/keys/public.pem",
			AccessTokenTTL: 15 * time.Minute, RefreshTokenTTL: 168 * time.Hour, SessionMaxAge: 720 * time.Hour, Issuer: "iam-service",
		},
		Admin:     AdminConfig{Email: "admin@example.com"},
		Casbin:    CasbinConfig{ModelPath: "configs/casbin_model.conf"},
		Lockout:   LockoutConfig{MaxAttempts: 5, Duration: 15 * time.Minute},
		Password:  PasswordConfig{MaxAge: 2160 * time.Hour},
		RateLimit: RateLimitConfig{RPS: 100, Burst: 200, LoginPerMinute: 5, LoginBurst: 10},
		Telemetry: TelemetryConfig{Endpoint: "localhost:4317", ServiceName: "iam-service", Environment: "development"},
	}
}

// validConfig returns a configuration that passes Validate outside dev mode.
func validConfig() Config {
	cfg := defaultConfig()
	cfg.Admin.Password = strongPassword
	return cfg
}

func TestLoad_Defaults(t *testing.T) {
	isolate(t)
	t.Setenv("ADMIN_PASSWORD", strongPassword)

	cfg, err := Load()
	require.NoError(t, err)

	assert.Empty(t, cfg.Server.TrustedProxies)
	assert.Empty(t, cfg.CORS.AllowedOrigins)
	cfg.Server.TrustedProxies, cfg.CORS.AllowedOrigins = nil, nil
	assert.Equal(t, validConfig(), *cfg)
}

func TestLoad_EnvironmentOverridesEveryDefault(t *testing.T) {
	isolate(t)
	overrides := map[string]string{
		"SERVER_PORT": "9090", "SERVER_READ_TIMEOUT": "30s", "SERVER_WRITE_TIMEOUT": "45s", "SERVER_SHUTDOWN_TIMEOUT": "5s",
		"TRUSTED_PROXIES": "10.0.0.1, 10.0.0.2",
		"LOG_LEVEL":       "debug", "LOG_FORMAT": "text",
		"DB_HOST": "db.internal", "DB_PORT": "6543", "DB_USER": "svc", "DB_PASSWORD": "pw", "DB_NAME": "iam_prod",
		"DB_SSLMODE": "require", "DB_MAX_OPEN_CONNS": "50", "DB_MAX_IDLE_CONNS": "10", "DB_MIGRATE": "false",
		"REDIS_HOST": "cache.internal", "REDIS_PORT": "6380", "REDIS_PASSWORD": "rpw", "REDIS_DB": "3",
		"JWT_PRIVATE_KEY_PATH": "/run/secrets/private.pem", "JWT_PUBLIC_KEY_PATH": "/run/secrets/public.pem",
		"JWT_ACCESS_TOKEN_TTL": "30m", "JWT_REFRESH_TOKEN_TTL": "720h", "JWT_SESSION_MAX_AGE": "0", "JWT_ISSUER": "iam-prod",
		"DEV_MODE":    "true",
		"ADMIN_EMAIL": "root@example.com", "ADMIN_PASSWORD": "Secret1!",
		"CASBIN_MODEL_PATH": "/etc/iam/model.conf", "AUTHZ_WATCHER_ENABLED": "true",
		"LOCKOUT_MAX_ATTEMPTS": "3", "LOCKOUT_DURATION": "1h",
		"PASSWORD_MAX_AGE": "0",
		"RATE_LIMIT_RPS":   "12.5", "RATE_LIMIT_BURST": "20", "LOGIN_RATE_LIMIT_PER_MIN": "2", "LOGIN_RATE_LIMIT_BURST": "4",
		"CORS_ALLOWED_ORIGINS": "https://app.example.com,https://admin.example.com",
		"OTEL_ENABLED":         "true", "OTEL_ENDPOINT": "otel-collector:4317", "OTEL_SERVICE_NAME": "iam-prod", "OTEL_ENVIRONMENT": "production",
	}
	assert.ElementsMatch(t, envNames(reflect.TypeFor[Config]()), slices.Collect(maps.Keys(overrides)),
		"every variable the configuration reads must be overridden by this test")
	setenv(t, overrides)

	cfg, err := Load()
	require.NoError(t, err)

	want := Config{
		Server: ServerConfig{
			Port: "9090", ReadTimeout: 30 * time.Second, WriteTimeout: 45 * time.Second, ShutdownTimeout: 5 * time.Second,
			TrustedProxies: []string{"10.0.0.1", "10.0.0.2"},
		},
		Log: LogConfig{Level: "debug", Format: "text"},
		Database: DatabaseConfig{
			Host: "db.internal", Port: "6543", User: "svc", Password: "pw", Name: "iam_prod", SSLMode: "require",
			MaxOpenConns: 50, MaxIdleConns: 10,
		},
		Redis: RedisConfig{Host: "cache.internal", Port: "6380", Password: "rpw", DB: 3},
		JWT: JWTConfig{
			PrivateKeyPath: "/run/secrets/private.pem", PublicKeyPath: "/run/secrets/public.pem",
			AccessTokenTTL: 30 * time.Minute, RefreshTokenTTL: 720 * time.Hour, SessionMaxAge: 0, Issuer: "iam-prod",
		},
		Admin:     AdminConfig{Email: "root@example.com", Password: "Secret1!"},
		Casbin:    CasbinConfig{ModelPath: "/etc/iam/model.conf", WatcherEnabled: true},
		Lockout:   LockoutConfig{MaxAttempts: 3, Duration: time.Hour},
		RateLimit: RateLimitConfig{RPS: 12.5, Burst: 20, LoginPerMinute: 2, LoginBurst: 4},
		CORS:      CORSConfig{AllowedOrigins: []string{"https://app.example.com", "https://admin.example.com"}},
		Telemetry: TelemetryConfig{Enabled: true, Endpoint: "otel-collector:4317", ServiceName: "iam-prod", Environment: "production"},
		DevMode:   true,
	}
	assert.Equal(t, want, *cfg)
}

func TestLoad_DotEnvDoesNotOverrideEnvironment(t *testing.T) {
	dir := isolate(t)
	writeDotEnv(t, dir, "SERVER_PORT=9999\nLOG_FORMAT=text\nJWT_ISSUER=from-dotenv\nJWT_ACCESS_TOKEN_TTL=5m\nDEV_MODE=true\n")
	t.Setenv("SERVER_PORT", "8081")
	t.Setenv("LOG_FORMAT", "")

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "8081", cfg.Server.Port, "a variable present in the environment wins over .env")
	assert.Empty(t, cfg.Log.Format, "a variable present but empty in the environment still wins over .env")
	assert.Equal(t, "from-dotenv", cfg.JWT.Issuer, ".env supplies the variables that are not set")
	assert.Equal(t, 5*time.Minute, cfg.JWT.AccessTokenTTL)
	assert.True(t, cfg.DevMode)
	assert.Equal(t, 168*time.Hour, cfg.JWT.RefreshTokenTTL, "defaults apply to everything else")
}

// TestLoad_ExampleFileIsValid keeps .env.example loadable, since the quick start copies it to .env.
func TestLoad_ExampleFileIsValid(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("..", "..", ".env.example"))
	require.NoError(t, err)
	dir := isolate(t)
	writeDotEnv(t, dir, string(example))

	cfg, err := Load()

	require.NoError(t, err)
	assert.True(t, cfg.DevMode, "the example is meant for local development")
	assert.Equal(t, "admin@example.com", cfg.Admin.Email)
}

func TestLoad_RejectsMalformedDotEnv(t *testing.T) {
	dir := isolate(t)
	writeDotEnv(t, dir, "DEV_MODE=true\nBAD-KEY=1\n")

	_, err := Load()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load .env")
}

func TestLoad_ParsesDurations(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
		get   func(*Config) time.Duration
		want  time.Duration
	}{
		{name: "minutes", key: "JWT_ACCESS_TOKEN_TTL", value: "15m", get: func(c *Config) time.Duration { return c.JWT.AccessTokenTTL }, want: 15 * time.Minute},
		{name: "hours", key: "JWT_REFRESH_TOKEN_TTL", value: "168h", get: func(c *Config) time.Duration { return c.JWT.RefreshTokenTTL }, want: 168 * time.Hour},
		{name: "mixed units", key: "LOCKOUT_DURATION", value: "1h30m", get: func(c *Config) time.Duration { return c.Lockout.Duration }, want: 90 * time.Minute},
		{name: "milliseconds", key: "SERVER_READ_TIMEOUT", value: "500ms", get: func(c *Config) time.Duration { return c.Server.ReadTimeout }, want: 500 * time.Millisecond},
		{name: "zero disables password expiry", key: "PASSWORD_MAX_AGE", value: "0", get: func(c *Config) time.Duration { return c.Password.MaxAge }, want: 0},
		{name: "zero disables the session bound", key: "JWT_SESSION_MAX_AGE", value: "0", get: func(c *Config) time.Duration { return c.JWT.SessionMaxAge }, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			t.Setenv("DEV_MODE", "true")
			t.Setenv(tt.key, tt.value)

			cfg, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tt.want, tt.get(cfg))
		})
	}
}

func TestLoad_RejectsUnparsableValues(t *testing.T) {
	tests := []struct {
		name  string
		key   string
		value string
	}{
		{name: "duration without a unit", key: "JWT_ACCESS_TOKEN_TTL", value: "15"},
		{name: "duration in words", key: "LOCKOUT_DURATION", value: "fifteen minutes"},
		{name: "integer", key: "DB_MAX_OPEN_CONNS", value: "many"},
		{name: "boolean", key: "DB_MIGRATE", value: "yes"},
		{name: "float", key: "RATE_LIMIT_RPS", value: "fast"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			t.Setenv("DEV_MODE", "true")
			t.Setenv(tt.key, tt.value)

			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "read environment")
			assert.Contains(t, err.Error(), tt.key)
		})
	}
}

func TestLoad_NormalizesValues(t *testing.T) {
	isolate(t)
	setenv(t, map[string]string{
		"DEV_MODE":             "true",
		"ADMIN_EMAIL":          "  Admin@Example.COM ",
		"CORS_ALLOWED_ORIGINS": " https://a.example , https://b.example ,",
		"TRUSTED_PROXIES":      " , ",
	})

	cfg, err := Load()
	require.NoError(t, err)

	assert.Equal(t, "admin@example.com", cfg.Admin.Email, "the admin email is trimmed and lower-cased")
	assert.Equal(t, []string{"https://a.example", "https://b.example"}, cfg.CORS.AllowedOrigins, "list entries are trimmed and empty ones dropped")
	assert.Empty(t, cfg.Server.TrustedProxies)
}

func TestLoad_AdminPassword(t *testing.T) {
	tests := []struct {
		name string
		env  map[string]string
		want string
	}{
		{name: "dev mode falls back to the default password", env: map[string]string{"DEV_MODE": "true"}, want: DevModeAdminPassword},
		{name: "dev mode keeps an explicit password", env: map[string]string{"DEV_MODE": "true", "ADMIN_PASSWORD": "Custom1!"}, want: "Custom1!"},
		{name: "dev mode accepts a weak password", env: map[string]string{"DEV_MODE": "true", "ADMIN_PASSWORD": "weak"}, want: "weak"},
		{name: "production keeps the explicit password", env: map[string]string{"ADMIN_PASSWORD": "Custom1!"}, want: "Custom1!"},
		{name: "production without seeding needs no password", env: map[string]string{"ADMIN_EMAIL": ""}, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolate(t)
			setenv(t, tt.env)

			cfg, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tt.want, cfg.Admin.Password)
		})
	}
}

func TestLoad_ProductionRequiresAStrongAdminPassword(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		isolate(t)

		_, err := Load()
		require.Error(t, err, "the bare defaults seed an admin without a password outside dev mode")
		assert.Contains(t, err.Error(), "ADMIN_PASSWORD")
	})
	t.Run("weak", func(t *testing.T) {
		isolate(t)
		t.Setenv("ADMIN_PASSWORD", "admin")

		_, err := Load()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ADMIN_PASSWORD does not meet the password policy")
		assert.Contains(t, err.Error(), "at least 8 characters")
		assert.NotContains(t, err.Error(), "admin\n", "the password itself is not echoed")
	})
}

func TestValidate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		mutate  func(c *Config)
		wantErr string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "dev mode without admin password", mutate: func(c *Config) { c.DevMode = true; c.Admin.Password = "" }},
		{name: "dev mode with a weak admin password", mutate: func(c *Config) { c.DevMode = true; c.Admin.Password = "weak" }},
		{name: "lowest port", mutate: func(c *Config) { c.Server.Port = "1" }},
		{name: "highest port", mutate: func(c *Config) { c.Server.Port = "65535" }},
		{name: "non-numeric port", mutate: func(c *Config) { c.Server.Port = "http" }, wantErr: "SERVER_PORT"},
		{name: "port zero", mutate: func(c *Config) { c.Server.Port = "0" }, wantErr: "SERVER_PORT"},
		{name: "port above range", mutate: func(c *Config) { c.Server.Port = "65536" }, wantErr: "SERVER_PORT"},
		{name: "unlimited pool", mutate: func(c *Config) { c.Database.MaxOpenConns = 0 }},
		{name: "pool of one connection deadlocks seeding", mutate: func(c *Config) { c.Database.MaxOpenConns = 1 }, wantErr: "DB_MAX_OPEN_CONNS"},
		{name: "negative pool size", mutate: func(c *Config) { c.Database.MaxOpenConns = -1 }, wantErr: "DB_MAX_OPEN_CONNS"},
		{name: "negative idle connections", mutate: func(c *Config) { c.Database.MaxIdleConns = -1 }, wantErr: "DB_MAX_IDLE_CONNS"},
		{name: "more idle than open connections", mutate: func(c *Config) { c.Database.MaxIdleConns = 30 }, wantErr: "DB_MAX_IDLE_CONNS must not exceed"},
		{name: "idle connections with an unlimited pool", mutate: func(c *Config) { c.Database.MaxOpenConns = 0; c.Database.MaxIdleConns = 30 }},
		{name: "zero access ttl", mutate: func(c *Config) { c.JWT.AccessTokenTTL = 0 }, wantErr: "JWT_ACCESS_TOKEN_TTL"},
		{name: "negative access ttl", mutate: func(c *Config) { c.JWT.AccessTokenTTL = -time.Minute }, wantErr: "JWT_ACCESS_TOKEN_TTL"},
		{name: "zero refresh ttl", mutate: func(c *Config) { c.JWT.RefreshTokenTTL = 0 }, wantErr: "JWT_REFRESH_TOKEN_TTL"},
		{name: "negative refresh ttl", mutate: func(c *Config) { c.JWT.RefreshTokenTTL = -time.Second }, wantErr: "JWT_REFRESH_TOKEN_TTL"},
		{name: "zero session max age disables the bound", mutate: func(c *Config) { c.JWT.SessionMaxAge = 0 }},
		{name: "negative session max age", mutate: func(c *Config) { c.JWT.SessionMaxAge = -time.Hour }, wantErr: "JWT_SESSION_MAX_AGE"},
		{name: "missing private key path", mutate: func(c *Config) { c.JWT.PrivateKeyPath = "" }, wantErr: "JWT_PRIVATE_KEY_PATH"},
		{name: "missing public key path", mutate: func(c *Config) { c.JWT.PublicKeyPath = "" }, wantErr: "JWT_PUBLIC_KEY_PATH"},
		{name: "production without admin password", mutate: func(c *Config) { c.Admin.Password = "" }, wantErr: "ADMIN_PASSWORD"},
		{name: "production with a weak admin password", mutate: func(c *Config) { c.Admin.Password = "admin123" }, wantErr: "ADMIN_PASSWORD does not meet"},
		{name: "production with seeding disabled", mutate: func(c *Config) { c.Admin.Email = ""; c.Admin.Password = "" }},
		{name: "lockout attempts zero", mutate: func(c *Config) { c.Lockout.MaxAttempts = 0 }, wantErr: "LOCKOUT_MAX_ATTEMPTS"},
		{name: "lockout attempts negative", mutate: func(c *Config) { c.Lockout.MaxAttempts = -1 }, wantErr: "LOCKOUT_MAX_ATTEMPTS"},
		{name: "zero lockout duration", mutate: func(c *Config) { c.Lockout.Duration = 0 }, wantErr: "LOCKOUT_DURATION"},
		{name: "zero password max age disables expiry", mutate: func(c *Config) { c.Password.MaxAge = 0 }},
		{name: "negative password max age", mutate: func(c *Config) { c.Password.MaxAge = -time.Hour }, wantErr: "PASSWORD_MAX_AGE"},
		{name: "zero rate", mutate: func(c *Config) { c.RateLimit.RPS = 0 }, wantErr: "RATE_LIMIT_RPS"},
		{name: "negative rate", mutate: func(c *Config) { c.RateLimit.RPS = -1 }, wantErr: "RATE_LIMIT_RPS"},
		{name: "zero burst rejects every request", mutate: func(c *Config) { c.RateLimit.Burst = 0 }, wantErr: "RATE_LIMIT_BURST"},
		{name: "zero login rate", mutate: func(c *Config) { c.RateLimit.LoginPerMinute = 0 }, wantErr: "LOGIN_RATE_LIMIT_PER_MIN"},
		{name: "zero login burst", mutate: func(c *Config) { c.RateLimit.LoginBurst = 0 }, wantErr: "LOGIN_RATE_LIMIT_BURST"},
		{name: "wildcard origin", mutate: func(c *Config) { c.CORS.AllowedOrigins = []string{"*"} }},
		{name: "origins with a scheme", mutate: func(c *Config) { c.CORS.AllowedOrigins = []string{"https://app.example.com", "http://*.local.test"} }},
		{name: "origin without a scheme", mutate: func(c *Config) { c.CORS.AllowedOrigins = []string{"app.example.com"} }, wantErr: "CORS_ALLOWED_ORIGINS"},
		{name: "origin with two wildcards", mutate: func(c *Config) { c.CORS.AllowedOrigins = []string{"https://*.*.example.com"} }, wantErr: "at most one wildcard"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			tt.mutate(&cfg)

			err := cfg.Validate()
			if tt.wantErr == "" {
				assert.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.wantErr)
		})
	}
}

func TestValidate_ReportsEveryProblem(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Server.Port = "x"
	cfg.Database.MaxOpenConns = 1
	cfg.JWT.AccessTokenTTL = 0
	cfg.JWT.RefreshTokenTTL = 0
	cfg.JWT.SessionMaxAge = -1
	cfg.JWT.PrivateKeyPath = ""
	cfg.JWT.PublicKeyPath = ""
	cfg.Admin.Password = ""
	cfg.Lockout.MaxAttempts = 0
	cfg.Lockout.Duration = 0
	cfg.Password.MaxAge = -1
	cfg.RateLimit = RateLimitConfig{}
	cfg.CORS.AllowedOrigins = []string{"nope"}

	err := cfg.Validate()
	require.Error(t, err)
	for _, name := range []string{
		"SERVER_PORT", "DB_MAX_OPEN_CONNS", "JWT_ACCESS_TOKEN_TTL", "JWT_REFRESH_TOKEN_TTL", "JWT_SESSION_MAX_AGE",
		"JWT_PRIVATE_KEY_PATH", "JWT_PUBLIC_KEY_PATH", "ADMIN_PASSWORD", "LOCKOUT_MAX_ATTEMPTS", "LOCKOUT_DURATION",
		"PASSWORD_MAX_AGE", "RATE_LIMIT_RPS", "RATE_LIMIT_BURST", "LOGIN_RATE_LIMIT_PER_MIN", "LOGIN_RATE_LIMIT_BURST",
		"CORS_ALLOWED_ORIGINS",
	} {
		assert.Contains(t, err.Error(), name)
	}
}

func TestConnectionHelpers(t *testing.T) {
	t.Parallel()
	cfg := validConfig()
	cfg.Database = DatabaseConfig{Host: "db", Port: "5432", User: "u", Password: "p", Name: "iam", SSLMode: "disable"}
	cfg.Redis = RedisConfig{Host: "cache", Port: "6379"}

	assert.Equal(t, "host='db' port='5432' user='u' password='p' dbname='iam' sslmode='disable' connect_timeout=5", cfg.DSN())
	assert.Equal(t, "cache:6379", cfg.RedisAddr())

	cfg.Redis.Host = "::1"
	assert.Equal(t, "[::1]:6379", cfg.RedisAddr(), "an IPv6 host is bracketed")
}

// TestDSN_RoundTripsThroughTheDriver parses the DSN with the driver the service uses, so that
// awkward credentials reach PostgreSQL unchanged instead of re-targeting the connection.
func TestDSN_RoundTripsThroughTheDriver(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		password string
	}{
		{"empty", ""},
		{"space", "with space"},
		{"single quote", "it's"},
		{"backslash", `back\slash`},
		{"keyword injection", "x sslmode=require"},
		{"quotes and backslashes", `a'b\'c\\d`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cfg := validConfig()
			cfg.Database = DatabaseConfig{Host: "db.internal", Port: "6543", User: "svc user", Password: tt.password, Name: "iam", SSLMode: "disable"}

			parsed, err := pgconn.ParseConfig(cfg.DSN())

			require.NoError(t, err)
			assert.Equal(t, "db.internal", parsed.Host)
			assert.Equal(t, uint16(6543), parsed.Port)
			assert.Equal(t, "svc user", parsed.User)
			assert.Equal(t, tt.password, parsed.Password)
			assert.Equal(t, "iam", parsed.Database)
			assert.Nil(t, parsed.TLSConfig, "sslmode=disable is kept")
			assert.Equal(t, dbConnectTimeout, parsed.ConnectTimeout)
		})
	}
}
