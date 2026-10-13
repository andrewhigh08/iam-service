package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/trace"
)

func logRecord(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	var rec map[string]any
	require.NoError(t, json.Unmarshal(buf.Bytes(), &rec), "log line: %s", buf.String())
	return rec
}

func TestDefaultConfig(t *testing.T) {
	t.Parallel()
	cfg := DefaultConfig()

	assert.Equal(t, "info", cfg.Level)
	assert.Equal(t, "json", cfg.Format)
	assert.True(t, cfg.AddSource)
	assert.Equal(t, time.RFC3339Nano, cfg.TimeFormat)
	assert.Same(t, os.Stdout, cfg.Output)
}

func TestNew_TimeFieldIsRFC3339NanoUTC(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Level: "info", Format: "json", Output: &buf})

	log.Info("hello")

	ts, ok := logRecord(t, &buf)["time"].(string)
	require.True(t, ok, "time must be a string")
	require.NotEmpty(t, ts)
	parsed, err := time.Parse(time.RFC3339Nano, ts)
	require.NoError(t, err)
	assert.True(t, strings.HasSuffix(ts, "Z"), "time must be rendered in UTC, got %q", ts)
	assert.WithinDuration(t, time.Now(), parsed, time.Minute)
}

func TestNew_CustomTimeFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", TimeFormat: time.DateOnly, Output: &buf})

	log.Info("hello")

	ts, ok := logRecord(t, &buf)["time"].(string)
	require.True(t, ok)
	_, err := time.Parse(time.DateOnly, ts)
	assert.NoError(t, err)
}

func TestNew_LevelThreshold(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		level     string
		threshold slog.Level
	}{
		{name: "debug", level: "debug", threshold: slog.LevelDebug},
		{name: "info", level: "info", threshold: slog.LevelInfo},
		{name: "warn", level: "warn", threshold: slog.LevelWarn},
		{name: "error", level: "error", threshold: slog.LevelError},
		{name: "empty defaults to info", level: "", threshold: slog.LevelInfo},
		{name: "unknown defaults to info", level: "verbose", threshold: slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			log := New(Config{Level: tt.level, Output: &bytes.Buffer{}})

			for _, lvl := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
				assert.Equal(t, lvl >= tt.threshold, log.Enabled(t.Context(), lvl), "level %s", lvl)
			}
		})
	}
}

func TestNew_LevelFiltersRecords(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Level: "warn", Output: &buf})

	log.Info("dropped")
	assert.Empty(t, buf.String())

	log.Warn("kept")
	assert.Contains(t, buf.String(), "kept")
}

func TestNew_TextFormat(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "text", Output: &buf})

	log.Info("hello", slog.String("key", "value"))

	line := buf.String()
	assert.Regexp(t, `^time=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z `, line)
	assert.Contains(t, line, "level=INFO")
	assert.Contains(t, line, "msg=hello")
	assert.Contains(t, line, "key=value")
}

func TestNew_UnknownFormatFallsBackToJSON(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "yaml", Output: &buf})

	log.Info("hello")

	rec := logRecord(t, &buf)
	assert.Equal(t, "hello", rec["msg"])
	assert.Equal(t, "INFO", rec["level"])
}

func TestNew_AddSource(t *testing.T) {
	t.Parallel()

	t.Run("enabled", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		log := New(Config{Format: "json", AddSource: true, Output: &buf})

		log.Info("hello")

		source, ok := logRecord(t, &buf)[slog.SourceKey].(map[string]any)
		require.True(t, ok, "source must be an object")
		file, _ := source["file"].(string)
		assert.True(t, strings.HasSuffix(file, "slog_test.go"), "source file %q must be the caller", file)
	})

	t.Run("disabled", func(t *testing.T) {
		t.Parallel()
		var buf bytes.Buffer
		log := New(Config{Format: "json", AddSource: false, Output: &buf})

		log.Info("hello")

		assert.NotContains(t, logRecord(t, &buf), slog.SourceKey)
	})
}

func TestFromContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", Output: &buf})

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    trace.TraceID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		SpanID:     trace.SpanID{1, 2, 3, 4, 5, 6, 7, 8},
		TraceFlags: trace.FlagsSampled,
	})
	ctx := WithRequestIDContext(t.Context(), "req-1")
	ctx = WithUserIDContext(ctx, 42)
	ctx = trace.ContextWithSpanContext(ctx, sc)

	log.FromContext(ctx).Info("hello")

	rec := logRecord(t, &buf)
	assert.Equal(t, "req-1", rec["request_id"])
	assert.InDelta(t, 42, rec["user_id"], 0)
	assert.Equal(t, sc.TraceID().String(), rec["trace_id"])
	assert.Equal(t, sc.SpanID().String(), rec["span_id"])
}

func TestFromContext_WithoutValues(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", Output: &buf})

	assert.Same(t, log, log.FromContext(t.Context()), "a context without values yields the same logger")

	log.FromContext(t.Context()).Info("hello")

	rec := logRecord(t, &buf)
	for _, key := range []string{"request_id", "user_id", "trace_id", "span_id"} {
		assert.NotContains(t, rec, key)
	}
}

func TestFromContext_SkipsMissingValues(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", Output: &buf})
	ctx := WithUserIDContext(WithRequestIDContext(t.Context(), "req-7"), 0)
	ctx = trace.ContextWithSpanContext(ctx, trace.SpanContext{})

	log.FromContext(ctx).Info("hello")

	rec := logRecord(t, &buf)
	assert.Equal(t, "req-7", rec["request_id"])
	assert.NotContains(t, rec, "user_id", "a zero user id is not logged")
	assert.NotContains(t, rec, "trace_id", "an invalid span context is not logged")
	assert.NotContains(t, rec, "span_id")
}

func TestContextHelpers(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	assert.Empty(t, RequestIDFromContext(ctx))
	assert.Zero(t, UserIDFromContext(ctx))

	ctx = WithUserIDContext(WithRequestIDContext(ctx, "abc"), 7)
	assert.Equal(t, "abc", RequestIDFromContext(ctx))
	assert.Equal(t, int64(7), UserIDFromContext(ctx))
}

func TestContextHelpers_IgnoreForeignKeys(t *testing.T) {
	t.Parallel()
	type foreignKey string
	ctx := context.WithValue(t.Context(), foreignKey("request_id"), "abc")
	ctx = context.WithValue(ctx, foreignKey("user_id"), int64(7))

	assert.Empty(t, RequestIDFromContext(ctx), "keys of another type must not collide with the package keys")
	assert.Zero(t, UserIDFromContext(ctx))
}

func TestWithComponent(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", Output: &buf})

	log.WithComponent("http").Info("hello")

	assert.Equal(t, "http", logRecord(t, &buf)["component"])
}

func TestWithComponent_ComposesWithFromContext(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	log := New(Config{Format: "json", Output: &buf})
	ctx := WithRequestIDContext(t.Context(), "req-1")

	log.WithComponent("http").FromContext(ctx).Info("hello")

	rec := logRecord(t, &buf)
	assert.Equal(t, "http", rec["component"])
	assert.Equal(t, "req-1", rec["request_id"])
}
