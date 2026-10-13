// Package logger provides structured logging functionality based on slog.
//
// Features:
//   - JSON and text output formats
//   - Context-aware logging (request ID, user ID, trace ID)
//   - Specialized logging methods for HTTP, DB, cache, auth
//   - Configurable log levels
//
// Usage example:
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
type contextKey string

// Context keys for storing values in context.
const (
	// RequestIDKey is the context key for request ID.
	RequestIDKey contextKey = "request_id"

	// UserIDKey is the context key for user ID.
	UserIDKey contextKey = "user_id"

	// TraceIDKey is the context key for trace ID (OpenTelemetry).
	TraceIDKey contextKey = "trace_id"
)

// Logger wraps slog.Logger with additional functionality.
type Logger struct {
	*slog.Logger
}

// Config holds logger configuration options.
type Config struct {
	Level      string    // Log level: "debug", "info", "warn", "error"
	Format     string    // Output format: "json", "text"
	AddSource  bool      // Include source file and line
	TimeFormat string    // Time format string
	Output     io.Writer // Output writer (default: os.Stdout)
}

// DefaultConfig returns the default logger configuration.
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
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}

	level := parseLevel(cfg.Level)

	opts := &slog.HandlerOptions{
		Level:     level,
		AddSource: cfg.AddSource,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			// Custom time formatting
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
func NewDefault() *Logger {
	return New(DefaultConfig())
}

// parseLevel converts a string level to slog.Level.
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
func (l *Logger) WithRequestID(requestID string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("request_id", requestID)),
	}
}

// WithUserID returns a logger with user ID field.
func (l *Logger) WithUserID(userID int64) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.Int64("user_id", userID)),
	}
}

// WithError returns a logger with error information.
func (l *Logger) WithError(err error) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("error", err.Error())),
	}
}

// WithFields returns a logger with additional custom fields.
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
func (l *Logger) WithComponent(component string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("component", component)),
	}
}

// WithService returns a logger with a service name field.
func (l *Logger) WithService(service string) *Logger {
	return &Logger{
		Logger: l.Logger.With(slog.String("service", service)),
	}
}

// LogRequest logs an HTTP request with method, path, status, duration, and client IP.
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
func (l *Logger) LogDBQuery(query string, duration time.Duration, rowsAffected int64) {
	l.Debug("database query",
		slog.String("query", query),
		slog.Duration("duration", duration),
		slog.Int64("rows_affected", rowsAffected),
	)
}

// LogCacheOperation logs a cache operation (get, set, delete) with hit/miss status.
func (l *Logger) LogCacheOperation(operation, key string, hit bool, duration time.Duration) {
	l.Debug("cache operation",
		slog.String("operation", operation),
		slog.String("key", key),
		slog.Bool("hit", hit),
		slog.Duration("duration", duration),
	)
}

// LogAuthAttempt logs an authentication attempt with success/failure status.
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
func (l *Logger) LogAuthzDecision(userID int64, resource, action string, allowed bool) {
	l.Debug("authz decision",
		slog.Int64("user_id", userID),
		slog.String("resource", resource),
		slog.String("action", action),
		slog.Bool("allowed", allowed),
	)
}

// Fatal logs a fatal error message and exits the application with code 1.
func (l *Logger) Fatal(msg string, args ...any) {
	// Add caller information
	_, file, line, _ := runtime.Caller(1)
	args = append(args, slog.String("caller", file), slog.Int("line", line))
	l.Error(msg, args...)
	os.Exit(1)
}

// Global logger instance.
var defaultLogger = NewDefault()

// Default returns the default global logger instance.
func Default() *Logger {
	return defaultLogger
}

// SetDefault sets the default global logger instance.
func SetDefault(l *Logger) {
	defaultLogger = l
}

// Context helper functions

// WithRequestIDContext adds a request ID to the context.
func WithRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, RequestIDKey, requestID)
}

// WithUserIDContext adds a user ID to the context.
func WithUserIDContext(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, UserIDKey, userID)
}

// WithTraceIDContext adds a trace ID to the context.
func WithTraceIDContext(ctx context.Context, traceID string) context.Context {
	return context.WithValue(ctx, TraceIDKey, traceID)
}

// GetRequestIDFromContext retrieves the request ID from context.
func GetRequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(RequestIDKey).(string); ok {
		return v
	}
	return ""
}

// GetUserIDFromContext retrieves the user ID from context.
func GetUserIDFromContext(ctx context.Context) int64 {
	if v, ok := ctx.Value(UserIDKey).(int64); ok {
		return v
	}
	return 0
}
