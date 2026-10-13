package pgrepo

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
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

func TestList_RejectsANonPositivePage(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		filter port.UserFilter
	}{
		{"zero page", port.UserFilter{Page: 0, PageSize: 10}},
		{"negative page", port.UserFilter{Page: -2, PageSize: 10}},
		{"zero page size", port.UserFilter{Page: 1, PageSize: 0}},
		{"negative page size", port.UserFilter{Page: 1, PageSize: -5}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			// No database is needed: the filter is rejected before any query runs.
			users, total, err := NewUserRepository(nil).List(t.Context(), tt.filter)

			var appErr *apperror.AppError
			require.ErrorAs(t, err, &appErr)
			assert.Equal(t, apperror.CodeInternal, appErr.Code)
			assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
			assert.Nil(t, users)
			assert.Zero(t, total)
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
