package telemetry

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

func TestInit_DisabledLeavesGlobalsUntouched(t *testing.T) {
	ctx := context.Background()
	tracerProvider := otel.GetTracerProvider()
	propagator := otel.GetTextMapPropagator()

	p, err := Init(ctx, Config{Enabled: false, ServiceName: "iam-service"})
	require.NoError(t, err)
	require.NotNil(t, p)

	require.NoError(t, p.Shutdown(ctx))
	assert.Equal(t, tracerProvider, otel.GetTracerProvider())
	assert.Equal(t, propagator, otel.GetTextMapPropagator())
}

func TestProvider_ShutdownOnNil(t *testing.T) {
	var p *Provider
	assert.NoError(t, p.Shutdown(context.Background()))
}
