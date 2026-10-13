package integration

import (
	"context"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/app"
	"github.com/andrewhigh08/iam-service/internal/domain"
)

// TestSecondInstanceReusesTheSeededDatabase boots another application on the same database
// and Redis, as a second replica would: it must find the administrator and the policies in
// place without duplicating them, serve the API, and stop cleanly. It is not parallel because
// app.New sets gin's package-level mode, which must not race with requests to the shared server.
func TestSecondInstanceReusesTheSeededDatabase(t *testing.T) {
	s := env(t)
	second, err := app.New(t.Context(), s.cfg, newLogger(), appVersion)
	require.NoError(t, err)

	db := openDB(t, s, postgresDB)
	var admins, policies int
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM users WHERE email = $1", adminEmail).Scan(&admins))
	assert.Equal(t, 1, admins)
	require.NoError(t, db.QueryRowContext(t.Context(), "SELECT count(*) FROM casbin_rule WHERE ptype = 'p'").Scan(&policies))
	assert.Len(t, domain.DefaultPolicies(), policies)

	srv := httptest.NewServer(second.Handler())
	defer srv.Close()
	c := &apiClient{baseURL: srv.URL, http: srv.Client()}
	c.adminToken(t)

	// Run returns once its context is canceled and releases everything; Close stays idempotent.
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.NoError(t, second.Run(ctx))
	require.NoError(t, second.Close())
}
