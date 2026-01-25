// Package telemetry provides OpenTelemetry instrumentation for distributed tracing.
// Пакет telemetry предоставляет инструментацию OpenTelemetry для распределённой трассировки.
package telemetry

import (
	"context"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds telemetry configuration.
type Config struct {
	ServiceName    string
	ServiceVersion string
	Environment    string
	OTLPEndpoint   string
	Enabled        bool
}

// DefaultConfig returns default telemetry configuration.
func DefaultConfig() Config {
	return Config{
		ServiceName:    "iam-service",
		ServiceVersion: "1.0.0",
		Environment:    "development",
		OTLPEndpoint:   "localhost:4317",
		Enabled:        false,
	}
}

// Provider wraps OpenTelemetry providers.
type Provider struct {
	TracerProvider *sdktrace.TracerProvider
	Tracer         trace.Tracer
}

// InitTelemetry initializes OpenTelemetry with the given configuration.
func InitTelemetry(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		// Return a no-op provider when disabled
		tp := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(tp)
		return &Provider{
			TracerProvider: tp,
			Tracer:         tp.Tracer(cfg.ServiceName),
		}, nil
	}

	// Create OTLP exporter
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.OTLPEndpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion(cfg.ServiceVersion),
			attribute.String("environment", cfg.Environment),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	// Create tracer provider
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)

	// Set global providers
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		TracerProvider: tp,
		Tracer:         tp.Tracer(cfg.ServiceName),
	}, nil
}

// Shutdown gracefully shuts down the telemetry provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.TracerProvider != nil {
		return p.TracerProvider.Shutdown(ctx)
	}
	return nil
}

// StartSpan starts a new span.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return p.Tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the current span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddSpanAttributes adds attributes to the current span.
func AddSpanAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// AddSpanEvent adds an event to the current span.
func AddSpanEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordError records an error in the current span.
func RecordError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
}

// Common attribute keys.
var (
	AttrUserID      = attribute.Key("user.id")
	AttrEmail       = attribute.Key("user.email")
	AttrResource    = attribute.Key("authz.resource")
	AttrAction      = attribute.Key("authz.action")
	AttrAllowed     = attribute.Key("authz.allowed")
	AttrCacheHit    = attribute.Key("cache.hit")
	AttrDBTable     = attribute.Key("db.table")
	AttrDBOperation = attribute.Key("db.operation")
)
