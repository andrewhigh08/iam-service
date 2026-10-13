package migrations_test

import (
	"io"
	"io/fs"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/migrations"
)

func TestEmbeddedMigrations(t *testing.T) {
	src, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)

	first, err := src.First()
	require.NoError(t, err)
	assert.Equal(t, uint(1), first)

	up, _, err := src.ReadUp(first)
	require.NoError(t, err)
	upSQL, err := io.ReadAll(up)
	require.NoError(t, err)
	assert.Contains(t, string(upSQL), "CREATE TABLE IF NOT EXISTS users")
	assert.Contains(t, string(upSQL), "CREATE TABLE IF NOT EXISTS audit_logs")
	assert.Contains(t, string(upSQL), "CREATE TABLE IF NOT EXISTS casbin_rule")
	assert.Contains(t, string(upSQL), "CREATE UNIQUE INDEX IF NOT EXISTS idx_casbin_rule")

	down, _, err := src.ReadDown(first)
	require.NoError(t, err)
	downSQL, err := io.ReadAll(down)
	require.NoError(t, err)
	assert.Contains(t, string(downSQL), "DROP TABLE IF EXISTS users")

	_, err = src.Next(first)
	assert.ErrorIs(t, err, fs.ErrNotExist, "expected no migration after the first, got %v", err)
}
