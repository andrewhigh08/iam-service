package integration

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"testing"
	"time"

	// Registers the pgx driver under the name "pgx" for database/sql.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// openDB opens a database/sql pool on database name of the suite's PostgreSQL and closes it
// when the test ends.
func openDB(t *testing.T, s *suite, name string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", s.dsnFor(name))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, db.Close()) })
	require.NoError(t, db.PingContext(t.Context()))
	return db
}

// auditRow is an audit_logs row as the tests read it.
type auditRow struct {
	ActorID      int64
	ResourceType string
	IP           string
	UserAgent    string
	Details      map[string]any
	CreatedAt    time.Time
}

// auditRows returns the entries recorded for action on resourceID, oldest first.
func auditRows(t *testing.T, db *sql.DB, action, resourceID string) []auditRow {
	t.Helper()
	rows, err := db.QueryContext(t.Context(), `
		SELECT actor_id, resource_type, COALESCE(host(ip_address), ''), COALESCE(user_agent, ''),
		       COALESCE(details::text, '{}'), created_at
		FROM audit_logs
		WHERE action = $1 AND resource_id = $2
		ORDER BY id`, action, resourceID)
	require.NoError(t, err)
	defer rows.Close()

	var out []auditRow
	for rows.Next() {
		var r auditRow
		var details string
		require.NoError(t, rows.Scan(&r.ActorID, &r.ResourceType, &r.IP, &r.UserAgent, &details, &r.CreatedAt))
		require.NoError(t, json.Unmarshal([]byte(details), &r.Details))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}

func TestAuditLogRecordsSecurityEvents(t *testing.T) {
	t.Parallel()
	s := env(t)
	c := newClient(t)
	db := openDB(t, s, postgresDB)

	admin := c.adminToken(t)
	acc := c.mustCreateUser(t, admin, roleViewer, false)
	c.mustLogin(t, acc.Email, acc.Password)
	for range lockoutMaxAttempts {
		requireError(t, c.login(t, acc.Email, wrongPassword), http.StatusUnauthorized, "UNAUTHORIZED")
	}
	requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED")
	userID := strconv.FormatInt(acc.ID, 10)

	created := auditRows(t, db, "user.create", userID)
	require.Len(t, created, 1)
	assert.Equal(t, parseClaims(t, admin).UserID, created[0].ActorID)
	assert.Equal(t, "user", created[0].ResourceType)
	assert.Equal(t, "127.0.0.1", created[0].IP)
	assert.Equal(t, "Go-http-client/1.1", created[0].UserAgent)
	assert.WithinDuration(t, time.Now(), created[0].CreatedAt, time.Minute)
	assert.Equal(t, map[string]any{
		"email": acc.Email, "full_name": "Integration viewer", "role": roleViewer, "temporary": false,
	}, created[0].Details)

	logins := auditRows(t, db, "auth.login.success", userID)
	require.Len(t, logins, 1)
	assert.Equal(t, acc.ID, logins[0].ActorID)
	assert.Equal(t, "user", logins[0].ResourceType)
	assert.Equal(t, "127.0.0.1", logins[0].IP)
	assert.Len(t, logins[0].Details["sid"], 16)

	failures := auditRows(t, db, "auth.login.failed", userID)
	require.Len(t, failures, lockoutMaxAttempts)
	for i, failure := range failures {
		assert.Equal(t, acc.ID, failure.ActorID)
		assert.Equal(t, map[string]any{
			"reason": "invalid_password", "attempts": float64(i + 1), "locked": i+1 == lockoutMaxAttempts,
		}, failure.Details)
	}

	// The locked attempt is filed under the address, since no account was involved yet.
	locked := auditRows(t, db, "auth.login.locked", acc.Email)
	require.Len(t, locked, 1)
	assert.Zero(t, locked[0].ActorID)
	assert.Equal(t, map[string]any{"reason": "too_many_failed_attempts"}, locked[0].Details)

	// The user's own actions are readable through the API by roles holding audit:read.
	trail := c.do(t, http.MethodGet, userPath(acc.ID, "/audit?limit=10"), nil, admin)
	requireStatus(t, trail, http.StatusOK)
	var entries auditEntriesData
	trail.decode(t, &entries)
	assert.Equal(t, len(entries.Entries), entries.Total)
	actions := make([]string, 0, len(entries.Entries))
	for _, e := range entries.Entries {
		assert.Equal(t, acc.ID, e.ActorID)
		assert.Equal(t, "127.0.0.1", e.IP)
		actions = append(actions, e.Action)
	}
	assert.Equal(t, "auth.login.failed", actions[0], "newest first")
	assert.Contains(t, actions, "auth.login.success")
	assert.Equal(t, map[string]any{"sid": logins[0].Details["sid"]}, entries.Entries[len(entries.Entries)-1].Details)
}

func TestAuditTrailIsReadableByAnalystsOnly(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	admin := c.adminToken(t)
	analyst := c.mustCreateUser(t, admin, roleAnalyst, false)
	viewer := c.mustCreateUser(t, admin, roleViewer, false)
	analystToken := c.mustLogin(t, analyst.Email, analyst.Password).AccessToken
	viewerToken := c.mustLogin(t, viewer.Email, viewer.Password).AccessToken

	trail := c.do(t, http.MethodGet, userPath(viewer.ID, "/audit"), nil, analystToken)
	requireStatus(t, trail, http.StatusOK)
	var entries auditEntriesData
	trail.decode(t, &entries)
	require.NotEmpty(t, entries.Entries, "the viewer's login was recorded")
	assert.Equal(t, "auth.login.success", entries.Entries[0].Action)

	requireError(t, c.do(t, http.MethodGet, userPath(viewer.ID, "/audit"), nil, viewerToken), http.StatusForbidden, "FORBIDDEN")
	requireError(t, c.do(t, http.MethodGet, userPath(viewer.ID, "/audit"), nil, ""), http.StatusUnauthorized, "UNAUTHORIZED")
	requireError(t, c.do(t, http.MethodGet, "/api/v1/users/abc/audit", nil, admin), http.StatusBadRequest, "BAD_REQUEST")
}
