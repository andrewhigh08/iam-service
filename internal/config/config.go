// Package config provides application configuration management.
// Пакет config обеспечивает управление конфигурацией приложения.
//
// Configuration is loaded from environment variables and optional .env file
// with validation at startup. Uses cleanenv for type-safe configuration.
// Конфигурация загружается из переменных окружения и опционального .env файла
// с валидацией при запуске. Использует cleanenv для типобезопасной конфигурации.
package config

import (
	"fmt"
	"os"

	"github.com/ilyakaznacheev/cleanenv"
)

// Config holds all application configuration.
// Config содержит всю конфигурацию приложения.
type Config struct {
	Server    ServerConfig    `yaml:"server"`                                     // HTTP server settings / Настройки HTTP сервера
	Database  DatabaseConfig  `yaml:"database"`                                   // PostgreSQL connection / Подключение к PostgreSQL
	Redis     RedisConfig     `yaml:"redis"`                                      // Redis connection / Подключение к Redis
	JWT       JWTConfig       `yaml:"jwt"`                                        // JWT token settings / Настройки JWT токенов
	Casbin    CasbinConfig    `yaml:"casbin"`                                     // Casbin RBAC settings / Настройки Casbin RBAC
	Telemetry TelemetryConfig `yaml:"telemetry"`                                  // OpenTelemetry settings / Настройки OpenTelemetry
	Lockout   LockoutConfig   `yaml:"lockout"`                                    // Account lockout settings / Настройки блокировки аккаунта
	Password  PasswordConfig  `yaml:"password"`                                   // Password policy settings / Настройки политики паролей
	DevMode   bool            `env:"DEV_MODE" env-default:"true" yaml:"dev_mode"` // Development mode / Режим разработки
}

// ServerConfig contains HTTP server configuration.
// ServerConfig содержит конфигурацию HTTP сервера.
type ServerConfig struct {
	Port string `env:"SERVER_PORT" env-default:"8080" yaml:"port"` // Server port / Порт сервера
}

// DatabaseConfig contains PostgreSQL connection settings.
// DatabaseConfig содержит настройки подключения к PostgreSQL.
type DatabaseConfig struct {
	Host     string `env:"DB_HOST" env-default:"localhost" yaml:"host"`            // Database host / Хост БД
	Port     string `env:"DB_PORT" env-default:"5432" yaml:"port"`                 // Database port / Порт БД
	User     string `env:"DB_USER" env-default:"iam_user" yaml:"user"`             // Database user / Пользователь БД
	Password string `env:"DB_PASSWORD" env-default:"iam_password" yaml:"password"` // Database password / Пароль БД
	DBName   string `env:"DB_NAME" env-default:"iam_db" yaml:"dbname"`             // Database name / Имя БД
	SSLMode  string `env:"DB_SSLMODE" env-default:"disable" yaml:"sslmode"`        // SSL mode / Режим SSL
}

// RedisConfig contains Redis connection settings.
// RedisConfig содержит настройки подключения к Redis.
type RedisConfig struct {
	Host     string `env:"REDIS_HOST" env-default:"localhost" yaml:"host"` // Redis host / Хост Redis
	Port     string `env:"REDIS_PORT" env-default:"6379" yaml:"port"`      // Redis port / Порт Redis
	Password string `env:"REDIS_PASSWORD" env-default:"" yaml:"password"`  // Redis password / Пароль Redis
	DB       int    `env:"REDIS_DB" env-default:"0" yaml:"db"`             // Redis database number / Номер БД Redis
}

// JWTConfig contains JWT token configuration.
// JWTConfig содержит конфигурацию JWT токенов.
type JWTConfig struct {
	Secret          string `env:"JWT_SECRET" env-default:"your-secret-key-change-in-production" yaml:"secret"`         // JWT signing secret / Секрет подписи
	AccessTokenTTL  int    `env:"JWT_ACCESS_TOKEN_TTL" env-default:"15" yaml:"access_token_ttl"`                       // Access token TTL in minutes / TTL access токена в минутах
	RefreshTokenTTL int    `env:"JWT_REFRESH_TOKEN_TTL" env-default:"7" yaml:"refresh_token_ttl"`                      // Refresh token TTL in days / TTL refresh токена в днях
	PrivateKeyPath  string `env:"JWT_PRIVATE_KEY_PATH" env-default:"configs/keys/private.pem" yaml:"private_key_path"` // Private key path / Путь к приватному ключу
	PublicKeyPath   string `env:"JWT_PUBLIC_KEY_PATH" env-default:"configs/keys/public.pem" yaml:"public_key_path"`    // Public key path / Путь к публичному ключу
}

// LockoutConfig contains account lockout configuration.
// LockoutConfig содержит конфигурацию блокировки аккаунта.
type LockoutConfig struct {
	MaxAttempts     int `env:"LOCKOUT_MAX_ATTEMPTS" env-default:"5" yaml:"max_attempts"`          // Max failed attempts / Макс. неудачных попыток
	LockoutDuration int `env:"LOCKOUT_DURATION_MINUTES" env-default:"15" yaml:"lockout_duration"` // Lockout duration in minutes / Длительность блокировки в минутах
}

// PasswordConfig contains password policy configuration.
// PasswordConfig содержит конфигурацию политики паролей.
type PasswordConfig struct {
	MaxAgeDays int `env:"PASSWORD_MAX_AGE_DAYS" env-default:"90" yaml:"max_age_days"` // Password max age in days (0 = no expiration) / Макс. срок действия в днях
}

// CasbinConfig contains Casbin RBAC configuration.
// CasbinConfig содержит конфигурацию Casbin RBAC.
type CasbinConfig struct {
	ModelPath string `env:"CASBIN_MODEL_PATH" env-default:"configs/casbin_model.conf" yaml:"model_path"` // Casbin model path / Путь к модели Casbin
}

// TelemetryConfig contains OpenTelemetry configuration.
// TelemetryConfig содержит конфигурацию OpenTelemetry.
type TelemetryConfig struct {
	Enabled      bool   `env:"OTEL_ENABLED" env-default:"false" yaml:"enabled"`                 // Enable telemetry / Включить телеметрию
	OTLPEndpoint string `env:"OTEL_ENDPOINT" env-default:"localhost:4317" yaml:"otlp_endpoint"` // OTLP endpoint / OTLP эндпоинт
	ServiceName  string `env:"OTEL_SERVICE_NAME" env-default:"iam-service" yaml:"service_name"` // Service name / Имя сервиса
	Environment  string `env:"OTEL_ENVIRONMENT" env-default:"development" yaml:"environment"`   // Environment / Окружение
}

// DSN returns the PostgreSQL connection string.
// DSN возвращает строку подключения к PostgreSQL.
func (c *DatabaseConfig) DSN() string {
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		c.Host, c.Port, c.User, c.Password, c.DBName, c.SSLMode)
}

// Load loads configuration from environment variables and optional .env file.
// Load загружает конфигурацию из переменных окружения и опционального .env файла.
//
// Configuration priority (highest to lowest):
// Приоритет конфигурации (от высшего к низшему):
//  1. Environment variables / Переменные окружения
//  2. .env file (if exists) / .env файл (если существует)
//  3. Default values / Значения по умолчанию
//
// Returns an error if required configuration is missing or invalid.
// Возвращает ошибку, если обязательная конфигурация отсутствует или некорректна.
func Load() (*Config, error) {
	var cfg Config

	// Try to load .env file if it exists (optional)
	// Пытаемся загрузить .env файл, если он существует (опционально)
	envFile := ".env"
	if _, err := os.Stat(envFile); err == nil {
		if err := cleanenv.ReadConfig(envFile, &cfg); err != nil {
			return nil, fmt.Errorf("failed to read .env file: %w", err)
		}
	} else {
		// No .env file, read from environment only
		// Нет .env файла, читаем только из окружения
		if err := cleanenv.ReadEnv(&cfg); err != nil {
			return nil, fmt.Errorf("failed to read environment variables: %w", err)
		}
	}

	return &cfg, nil
}

// MustLoad loads configuration and panics on error.
// MustLoad загружает конфигурацию и паникует при ошибке.
//
// Use this in main() when configuration is critical for startup.
// Используйте в main(), когда конфигурация критична для запуска.
func MustLoad() *Config {
	cfg, err := Load()
	if err != nil {
		panic(fmt.Sprintf("failed to load configuration: %v", err))
	}
	return cfg
}

// GetDescription returns a description of all configuration parameters.
// GetDescription возвращает описание всех параметров конфигурации.
//
// Useful for generating help text or documentation.
// Полезно для генерации справочного текста или документации.
func GetDescription() (string, error) {
	var cfg Config
	return cleanenv.GetDescription(&cfg, nil)
}
