package integration

import (
	"database/sql"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/adapter/pgrepo"
	"github.com/andrewhigh08/iam-service/migrations"
)

// migrationsDB is a database of its own for the schema round trip, so that dropping the
// tables never touches the application under test.
const migrationsDB = "iam_migrations_test"

func TestMigrationsRollBackAndReapplyCleanly(t *testing.T) {
	t.Parallel()
	s := env(t)
	control := openDB(t, s, postgresDB)
	_, err := control.ExecContext(t.Context(), "DROP DATABASE IF EXISTS "+migrationsDB+" WITH (FORCE)")
	require.NoError(t, err)
	_, err = control.ExecContext(t.Context(), "CREATE DATABASE "+migrationsDB)
	require.NoError(t, err)
	db := openDB(t, s, migrationsDB)

	require.NoError(t, pgrepo.Migrate(t.Context(), db, migrations.FS))
	assertSchema(t, db, true)
	// An up-to-date schema is left alone.
	require.NoError(t, pgrepo.Migrate(t.Context(), db, migrations.FS))
	assertSchema(t, db, true)

	m := newMigrator(t, db)
	require.NoError(t, m.Down())
	assertSchema(t, db, false)
	_, _, err = m.Version()
	require.ErrorIs(t, err, migrate.ErrNilVersion)

	require.NoError(t, pgrepo.Migrate(t.Context(), db, migrations.FS))
	assertSchema(t, db, true)
	version, dirty, err := m.Version()
	require.NoError(t, err)
	assert.Equal(t, uint(1), version)
	assert.False(t, dirty)
}

// newMigrator builds a golang-migrate instance over the embedded migrations on a dedicated
// connection of db that is released when the test ends.
func newMigrator(t *testing.T, db *sql.DB) *migrate.Migrate {
	t.Helper()
	conn, err := db.Conn(t.Context())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, conn.Close()) })
	driver, err := pgmigrate.WithConnection(t.Context(), conn, &pgmigrate.Config{})
	require.NoError(t, err)
	source, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	require.NoError(t, err)
	return m
}

// assertSchema checks that the tables and indexes of the schema all exist, or that none does.
func assertSchema(t *testing.T, db *sql.DB, present bool) {
	t.Helper()
	var tables, indexes int
	require.NoError(t, db.QueryRowContext(t.Context(), `
		SELECT count(*) FROM information_schema.tables
		WHERE table_schema = 'public' AND table_name IN ('users', 'audit_logs', 'casbin_rule')`).Scan(&tables))
	require.NoError(t, db.QueryRowContext(t.Context(), `
		SELECT count(*) FROM pg_indexes
		WHERE schemaname = 'public' AND indexname IN ('idx_audit_logs_actor', 'idx_audit_logs_resource', 'idx_casbin_rule')`).Scan(&indexes))
	if present {
		assert.Equal(t, 3, tables)
		assert.Equal(t, 3, indexes)
		return
	}
	assert.Zero(t, tables)
	assert.Zero(t, indexes)
}
