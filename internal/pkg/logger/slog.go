// Package logger provides structured logging functionality based on slog.
// Пакет logger предоставляет функциональность структурированного логирования на базе slog.
//
// Features / Возможности:
//   - JSON and text output formats / Форматы вывода JSON и text
//   - Context-aware logging (request ID, user ID, trace ID) / Логирование с контекстом
//   - Specialized logging methods for HTTP, DB, cache, auth / Специализированные методы логирования
//   - Configurable log levels / Настраиваемые уровни логирования
//
// Usage example / Пример использования:
//
//	log := logger.New(logger.Config{Level: "info", Format: "json"})
//	log.Info("server started", slog.String("port", "8080"))
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"runtime"
	"time"
)

// contextKey is a custom type for context keys to avoid collisions.
// contextKey — пользовательский тип для ключей контекста во избежание коллизий.
type contextKey string

// Context keys for storing values in context.
// Ключи контекста для хранения значений в контексте.
const (
	// RequestIDKey is the context key for request ID.
	// RequestIDKey — ключ контекста для ID запроса.
	RequestIDKey contextKey = "request_id"

	// UserIDKey is the context key for user ID.
	// UserIDKey — ключ контекста для ID пользователя.
	UserIDKey contextKey = "user_id"

	// TraceIDKey is the context key for trace ID (OpenTelemetry).
	// TraceIDKey — ключ контекста для ID трассировки (OpenTelemetry).
	TraceIDKey contextKey = "trace_id"
)

// Logger wraps slog.Logger with additional functionality.
// Logger оборачивает slog.Logger с дополнительной функциональностью.
type Logger struct {
	*slog.Logger
}

// Config holds logger configuration options.
// Config содержит параметры конфигурации логгера.
type Config struct {
	Level      string    // Log level: "debug", "info", "warn", "error" / Уровень: "debug", "info", "warn", "error"
	Format     string    // Output format: "json", "text" / Формат вывода: "json", "text"
	AddSource  bool      // Include source file and line / Включать файл и строку исходника
	TimeFormat string    // Time format string / Формат времени
	Output     io.Writer // Output writer (default: os.Stdout) / Writer для вывода (по умолчанию: os.Stdout)
}

// DefaultConfig returns the default logger configuration.
// DefaultConfig возвращает конфигурацию логгера по умолчанию.
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		AddSource:  true,
		TimeFormat: time.RFC3339,
		Output:     os.Stdout,
	}
}

// New creates a new Logger with the given configuration.
// New создаёт новый Logger с заданной конфигурацией.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	level := parseLevel(cfg.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Custom time formatting / Пользовательское форматирование времени
			if a.Key == slog.TimeKey {
				if t, ok := a.Value.Any().(time.Time); ok {
					return slog.String(slog.TimeKey, t.Format(cfg.TimeFormat))
				}
			}
			return a
		},
	}

	var handler slog.Handler
	if cfg.Format == "text" {
		handler = slog.NewTextHandler(cfg.Output, opts)
	} else {
		handler = slog.NewJSONHandler(cfg.Output, opts)
	}

	return &Logger{
		Logger: slog.New(handler),
	}
}

// NewDefault creates a logger with default configuration.
// NewDefault создаёт логгер с конфигурацией по умолчанию.
func NewDefault() *Logger {
	return New(DefaultConfig())
}

// parseLevel converts a string level to slog.Level.
// parseLevel преобразует строковый уровень в slog.Level.
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "info":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithContext returns a logger enriched with context values (request_id, user_id, trace_id).
// WithContext возвращает логгер, обогащённый значениями из контекста (request_id, user_id, trace_id).
func (l *Logger) WithContext(ctx context.Context) *Logger {
	attrs := make([]any, 0)

	if requestID, ok := ctx.Value(RequestIDKey).(string); ok && requestID != "" {
		attrs = append(attrs, slog.String("request_id", requestID))
	}
	if userID, ok := ctx.Value(UserIDKey).(int64); ok && userID != 0 {
		attrs = append(attrs, slog.Int64("user_id", userID))
	}
	if traceID, ok := ctx.Value(TraceIDKey).(string); ok && traceID != "" {
		attrs = append(attrs, slog.String("trace_id", traceID))
	}

	if len(attrs) == 0 {
		return l
	}

	return &Logger{
		Logger: l.Logger.With(attrs...),
	}
}

// WithRequestID returns a logger with request ID field.
// WithRequestID возвращает логгер с полем request ID.
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("request_id", requestID)),
	}
}

// WithUserID returns a logger with user ID field.
// WithUserID возвращает логгер с полем user ID.
func (l *Logger) WithUserID(userID int64) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.Int64("user_id", userID)),
	}
}

// WithError returns a logger with error information.
// WithError возвращает логгер с информацией об ошибке.
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("error", err.Error())),
	}
}

// WithFields returns a logger with additional custom fields.
// WithFields возвращает логгер с дополнительными пользовательскими полями.
func (l *Logger) WithFields(fields map[string]interface{}) *Logger {
	attrs := make([]any, 0, len(fields)*2)
	for k, v := range fields {
		attrs = append(attrs, slog.Any(k, v))
	}
	return &Logger{
		Logger: l.Logger.With(attrs...),
	}
}

// WithComponent returns a logger with a component name field.
// WithComponent возвращает логгер с полем имени компонента.
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("component", component)),
	}
}

// WithService returns a logger with a service name field.
// WithService возвращает логгер с полем имени сервиса.
func (l *Logger) WithService(service string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("service", service)),
	}
}

// LogRequest logs an HTTP request with method, path, status, duration, and client IP.
// LogRequest логирует HTTP запрос с методом, путём, статусом, длительностью и IP клиента.
func (l *Logger) LogRequest(method, path string, statusCode int, duration time.Duration, clientIP string) {
	l.Info("http request",
		slog.String("method", method),
		slog.String("path", path),
		slog.Int("status", statusCode),
		slog.Duration("duration", duration),
		slog.String("client_ip", clientIP),
	)
}

// LogDBQuery logs a database query with query string, duration, and rows affected.
// LogDBQuery логирует запрос к БД с текстом запроса, длительностью и количеством затронутых строк.
func (l *Logger) LogDBQuery(query string, duration time.Duration, rowsAffected int64) {
	l.Debug("database query",
		slog.String("query", query),
		slog.Duration("duration", duration),
		slog.Int64("rows_affected", rowsAffected),
	)
}

// LogCacheOperation logs a cache operation (get, set, delete) with hit/miss status.
// LogCacheOperation логирует операцию кэша (get, set, delete) со статусом hit/miss.
func (l *Logger) LogCacheOperation(operation, key string, hit bool, duration time.Duration) {
	l.Debug("cache operation",
		slog.String("operation", operation),
		slog.String("key", key),
		slog.Bool("hit", hit),
		slog.Duration("duration", duration),
	)
}

// LogAuthAttempt logs an authentication attempt with success/failure status.
// LogAuthAttempt логирует попытку аутентификации со статусом успех/неудача.
func (l *Logger) LogAuthAttempt(email string, success bool, reason string) {
	level := slog.LevelInfo
	if !success {
		level = slog.LevelWarn
	}
	l.Log(context.Background(), level, "auth attempt",
		slog.String("email", email),
		slog.Bool("success", success),
		slog.String("reason", reason),
	)
}

// LogAuthzDecision logs an authorization decision (allow/deny).
// LogAuthzDecision логирует решение авторизации (разрешить/запретить).
func (l *Logger) LogAuthzDecision(userID int64, resource, action string, allowed bool) {
	l.Debug("authz decision",
		slog.Int64("user_id", userID),
		slog.String("resource", resource),
		slog.String("action", action),
		slog.Bool("allowed", allowed),
	)
}

// Fatal logs a fatal error message and exits the application with code 1.
// Fatal логирует фатальную ошибку и завершает приложение с кодом 1.
func (l *Logger) Fatal(msg string, args ...any) {
	// Add caller information / Добавляем информацию о вызывающем
	_, file, line, _ := runtime.Caller(1)
	args = append(args, slog.String("caller", file), slog.Int("line", line))
	l.Error(msg, args...)
	os.Exit(1)
}

// Global logger instance.
// Глобальный экземпляр логгера.
var defaultLogger = NewDefault()

// Default returns the default global logger instance.
// Default возвращает глобальный экземпляр логгера по умолчанию.
func Default() *Logger {
	return defaultLogger
}

// SetDefault sets the default global logger instance.
// SetDefault устанавливает глобальный экземпляр логгера по умолчанию.
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Context helper functions / Вспомогательные функции для контекста

// WithRequestIDContext adds a request ID to the context.
// WithRequestIDContext добавляет ID запроса в контекст.
func WithRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithUserIDContext adds a user ID to the context.
// WithUserIDContext добавляет ID пользователя в контекст.
func WithUserIDContext(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithTraceIDContext adds a trace ID to the context.
// WithTraceIDContext добавляет ID трассировки в контекст.
func WithTraceIDContext(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetRequestIDFromContext retrieves the request ID from context.
// GetRequestIDFromContext извлекает ID запроса из контекста.
func GetRequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}

// GetUserIDFromContext retrieves the user ID from context.
// GetUserIDFromContext извлекает ID пользователя из контекста.
func GetUserIDFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(UserIDKey).(int64); ok {
		return v
	}
	return 0
}
