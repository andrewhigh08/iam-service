package pgrepo

import (
	"context"
	"database/sql"
	"errors"
	"io/fs"

	"github.com/golang-migrate/migrate/v4"
	pgmigrate "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

// Migrate applies every pending migration in the root of src (golang-migrate file layout) to db.
// An already up-to-date schema is not an error; ctx bounds the connection setup.
func Migrate(ctx context.Context, db *sql.DB, src fs.FS) error {
	// A dedicated connection is borrowed and returned here: the driver built on the pool itself
	// would keep its connection checked out for the lifetime of the process.
	conn, err := db.Conn(ctx)
	if err != nil {
		return apperror.Internal("failed to acquire a migration connection", err)
	}
	defer func() { _ = conn.Close() }()

	driver, err := pgmigrate.WithConnection(ctx, conn, &pgmigrate.Config{})
	if err != nil {
		return apperror.Internal("failed to set up the migration driver", err)
	}
	source, err := iofs.New(src, ".")
	if err != nil {
		return apperror.Internal("failed to open the migration source", err)
	}
	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return apperror.Internal("failed to set up migrations", err)
	}

	err = m.Up()
	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return apperror.Internal("failed to apply migrations", err)
	}
	return nil
}
