package pgrepo

import (
	"net/http"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
)

func TestListByUser_RejectsANonPositiveLimit(t *testing.T) {
	t.Parallel()
	for _, limit := range []int{0, -1} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			t.Parallel()
			// No database is needed: the limit is rejected before any query runs.
			entries, err := NewAuditLogRepository(nil).ListByUser(t.Context(), 7, limit)

			var appErr *apperror.AppError
			require.ErrorAs(t, err, &appErr)
			assert.Equal(t, apperror.CodeInternal, appErr.Code)
			assert.Equal(t, http.StatusInternalServerError, appErr.HTTPStatus)
			assert.Nil(t, entries)
		})
	}
}
