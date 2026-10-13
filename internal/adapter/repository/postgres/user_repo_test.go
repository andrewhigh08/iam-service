package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
)

func TestLikeEscaper(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want string
	}{
		{"alice", "alice"},
		{"50%", `50\%`},
		{"a_b", `a\_b`},
		{`back\slash`, `back\\slash`},
		{`%_\`, `\%\_\\`},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, likeEscaper.Replace(tt.in))
		})
	}
}

func TestNormalizePage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		page     int
		size     int
		wantPage int
		wantSize int
	}{
		{"valid values pass through", 3, 25, 3, 25},
		{"zero page becomes the first", 0, 25, 1, 25},
		{"negative page becomes the first", -2, 25, 1, 25},
		{"zero size gets the default", 1, 0, 1, defaultPageSize},
		{"negative size gets the default", 1, -5, 1, defaultPageSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			page, size := normalizePage(tt.page, tt.size)

			assert.Equal(t, tt.wantPage, page)
			assert.Equal(t, tt.wantSize, size)
		})
	}
}

func TestIsUniqueViolation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, false},
		{"gorm translated duplicate", gorm.ErrDuplicatedKey, true},
		{"wrapped gorm duplicate", fmt.Errorf("insert: %w", gorm.ErrDuplicatedKey), true},
		{"postgres unique violation", &pgconn.PgError{Code: uniqueViolation}, true},
		{"wrapped postgres unique violation", fmt.Errorf("insert: %w", &pgconn.PgError{Code: uniqueViolation}), true},
		{"other postgres error", &pgconn.PgError{Code: "23503"}, false},
		{"record not found", gorm.ErrRecordNotFound, false},
		{"plain error", errors.New("boom"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, isUniqueViolation(tt.err))
		})
	}
}
