// Package config provides application configuration management.
//
// Configuration is loaded from environment variables and optional .env file
// with validation at startup. Uses cleanenv for type-safe configuration.
package config

import (
	"fmt"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config holds all application configuration.
type Config struct {
	Server    ServerConfig    `yaml:"server"`                                     // HTTP server settings
	Database  DatabaseConfig  `yaml:"database"`                                   // PostgreSQL connection
	Redis     RedisConfig     `yaml:"redis"`                                      // Redis connection
	JWT       JWTConfig       `yaml:"jwt"`                                        // JWT token settings
	Casbin    CasbinConfig    `yaml:"casbin"`                                     // Casbin RBAC settings
	Telemetry TelemetryConfig `yaml:"telemetry"`                                  // OpenTelemetry settings
	Lockout   LockoutConfig   `yaml:"lockout"`                                    // Account lockout settings
	Password  PasswordConfig  `yaml:"password"`                                   // Password policy settings
	DevMode   bool            `env:"DEV_MODE" env-default:"true" yaml:"dev_mode"` // Development mode
}

// ServerConfig contains HTTP server configuration.
type ServerConfig struct {
	Port string `env:"SERVER_PORT" env-default:"8080" yaml:"port"` // Server port
}

// DatabaseConfig contains PostgreSQL connection settings.
type DatabaseConfig struct {
	Host     string `env:"DB_HOST" env-default:"localhost" yaml:"host"`            // Database host
	Port     string `env:"DB_PORT" env-default:"5432" yaml:"port"`                 // Database port
	User     string `env:"DB_USER" env-default:"iam_user" yaml:"user"`             // Database user
	Password string `env:"DB_PASSWORD" env-default:"iam_password" yaml:"password"` // Database password
	DBName   string `env:"DB_NAME" env-default:"iam_db" yaml:"dbname"`             // Database name
	SSLMode  string `env:"DB_SSLMODE" env-default:"disable" yaml:"sslmode"`        // SSL mode
}

// RedisConfig contains Redis connection settings.
type RedisConfig struct {
	Host     string `env:"REDIS_HOST" env-default:"localhost" yaml:"host"` // Redis host
	Port     string `env:"REDIS_PORT" env-default:"6379" yaml:"port"`      // Redis port
	Password string `env:"REDIS_PASSWORD" env-default:"" yaml:"password"`  // Redis password
	DB       int    `env:"REDIS_DB" env-default:"0" yaml:"db"`             // Redis database number
}

// JWTConfig contains JWT token configuration.
type JWTConfig struct {
	Secret          string `env:"JWT_SECRET" env-default:"your-secret-key-change-in-production" yaml:"secret"`         // JWT signing secret
	AccessTokenTTL  int    `env:"JWT_ACCESS_TOKEN_TTL" env-default:"15" yaml:"access_token_ttl"`                       // Access token TTL in minutes
	RefreshTokenTTL int    `env:"JWT_REFRESH_TOKEN_TTL" env-default:"7" yaml:"refresh_token_ttl"`                      // Refresh token TTL in days
	PrivateKeyPath  string `env:"JWT_PRIVATE_KEY_PATH" env-default:"configs/keys/private.pem" yaml:"private_key_path"` // Private key path
	PublicKeyPath   string `env:"JWT_PUBLIC_KEY_PATH" env-default:"configs/keys/public.pem" yaml:"public_key_path"`    // Public key path
}

// LockoutConfig contains account lockout configuration.
type LockoutConfig struct {
	MaxAttempts     int `env:"LOCKOUT_MAX_ATTEMPTS" env-default:"5" yaml:"max_attempts"`          // Max failed attempts
	LockoutDuration int `env:"LOCKOUT_DURATION_MINUTES" env-default:"15" yaml:"lockout_duration"` // Lockout duration in minutes
}

// PasswordConfig contains password policy configuration.
type PasswordConfig struct {
	MaxAgeDays int `env:"PASSWORD_MAX_AGE_DAYS" env-default:"90" yaml:"max_age_days"` // Password max age in days (0 = no expiration)
}

// CasbinConfig contains Casbin RBAC configuration.
type CasbinConfig struct {
	ModelPath string `env:"CASBIN_MODEL_PATH" env-default:"configs/casbin_model.conf" yaml:"model_path"` // Casbin model path
}

// TelemetryConfig contains OpenTelemetry configuration.
type TelemetryConfig struct {
	Enabled      bool   `env:"OTEL_ENABLED" env-default:"false" yaml:"enabled"`                 // Enable telemetry
	OTLPEndpoint string `env:"OTEL_ENDPOINT" env-default:"localhost:4317" yaml:"otlp_endpoint"` // OTLP endpoint
	ServiceName  string `env:"OTEL_SERVICE_NAME" env-default:"iam-service" yaml:"service_name"` // Service name
	Environment  string `env:"OTEL_ENVIRONMENT" env-default:"development" yaml:"environment"`   // Environment
}

// DSN returns the PostgreSQL connection string.
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}

// Load loads configuration from environment variables and optional .env file.
//
// Configuration priority (highest to lowest):
//  1. Environment variables
//  2. .env file (if exists)
//  3. Default values
//
// Returns an error if required configuration is missing or invalid.
func Load() (*Config, error) {
	var cfg Config

	// Try to load .env file if it exists (optional)
	envFile := ".env"
	if _, err := os.Stat(envFile); err == nil {
		if err := cleanenv.ReadConfig(envFile, &cfg); err != nil {
			return nil, fmt.Errorf("failed to read .env file: %w", err)
		}
	} else {
		// No .env file, read from environment only
		if err := cleanenv.ReadEnv(&cfg); err != nil {
			return nil, fmt.Errorf("failed to read environment variables: %w", err)
		}
	}

	return &cfg, nil
}

// MustLoad loads configuration and panics on error.
//
// Use this in main() when configuration is critical for startup.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load configuration: %v", err))
	}
	return cfg
}

// GetDescription returns a description of all configuration parameters.
//
// Useful for generating help text or documentation.
func GetDescription() (string, error) {
	var cfg Config
	return cleanenv.GetDescription(&cfg, nil)
}
