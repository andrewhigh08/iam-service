// Package logger provides a slog-based structured logger enriched from the request context.
package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// contextKey is the private type of the keys stored in a context by this package.
type contextKey string

const (
	requestIDKey contextKey = "request_id"
	userIDKey    contextKey = "user_id"
)

// Logger wraps slog.Logger.
type Logger struct {
	*slog.Logger
}

// Config controls the logger output.
type Config struct {
	Level      string    // "debug", "info", "warn" or "error"; anything else means "info"
	Format     string    // "json" (default) or "text"
	AddSource  bool      // include the calling file and line
	TimeFormat string    // layout of the time field; defaults to time.RFC3339Nano
	Output     io.Writer // defaults to os.Stdout
}

// DefaultConfig returns an info-level JSON configuration writing to stdout.
func DefaultConfig() Config {
	return Config{
		Level:      "info",
		Format:     "json",
		AddSource:  true,
		TimeFormat: time.RFC3339Nano,
		Output:     os.Stdout,
	}
}

// New builds a Logger from cfg. Timestamps are rendered in UTC using cfg.TimeFormat.
func New(cfg Config) *Logger {
	if cfg.Output == nil {
		cfg.Output = os.Stdout
	}
	if cfg.TimeFormat == "" {
		cfg.TimeFormat = time.RFC3339Nano
	}

	opts := &slog.HandlerOptions{
		Level:     parseLevel(cfg.Level),
		AddSource: cfg.AddSource,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) == 0 && a.Key == slog.TimeKey && a.Value.Kind() == slog.KindTime {
				return slog.String(slog.TimeKey, a.Value.Time().UTC().Format(cfg.TimeFormat))
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
	return &Logger{Logger: slog.New(handler)}
}

// parseLevel maps a level name to a slog.Level, defaulting to info.
func parseLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// WithComponent returns a logger tagged with a component name.
func (l *Logger) WithComponent(name string) *Logger {
	return &Logger{Logger: l.With(slog.String("component", name))}
}

// FromContext returns a logger carrying the request id, user id and OpenTelemetry trace and
// span ids found in ctx. Missing values are skipped.
func (l *Logger) FromContext(ctx context.Context) *Logger {
	attrs := make([]any, 0, 4)
	if id := RequestIDFromContext(ctx); id != "" {
		attrs = append(attrs, slog.String("request_id", id))
	}
	if id := UserIDFromContext(ctx); id != 0 {
		attrs = append(attrs, slog.Int64("user_id", id))
	}
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		attrs = append(attrs,
			slog.String("trace_id", sc.TraceID().String()),
			slog.String("span_id", sc.SpanID().String()),
		)
	}
	if len(attrs) == 0 {
		return l
	}
	return &Logger{Logger: l.With(attrs...)}
}

// WithRequestIDContext stores the request id in ctx.
func WithRequestIDContext(ctx context.Context, requestID string) context.Context {
	return context.WithValue(ctx, requestIDKey, requestID)
}

// WithUserIDContext stores the authenticated user id in ctx.
func WithUserIDContext(ctx context.Context, userID int64) context.Context {
	return context.WithValue(ctx, userIDKey, userID)
}

// RequestIDFromContext returns the request id stored in ctx, or "" when there is none.
func RequestIDFromContext(ctx context.Context) string {
	id, _ := ctx.Value(requestIDKey).(string)
	return id
}

// UserIDFromContext returns the user id stored in ctx, or 0 when there is none.
func UserIDFromContext(ctx context.Context) int64 {
	id, _ := ctx.Value(userIDKey).(int64)
	return id
}
