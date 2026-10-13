// Package migrations embeds the SQL schema migrations applied with golang-migrate.
package migrations

import "embed"

// FS holds the embedded *.sql migration files.
//
//go:embed *.sql
var FS embed.FS
