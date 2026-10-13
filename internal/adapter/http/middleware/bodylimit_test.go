package middleware

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testBodyLimit int64 = 32

func TestDefaultBodyLimit(t *testing.T) {
	t.Parallel()
	limit := DefaultBodyLimit
	assert.Equal(t, int64(1<<20), limit)
}

func TestBodyLimit_ReadingPastTheLimitFails(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{"below the limit", strings.Repeat("a", 10), false},
		{"exactly the limit", strings.Repeat("a", int(testBodyLimit)), false},
		{"one byte over the limit", strings.Repeat("a", int(testBodyLimit)+1), true},
		{"far over the limit", strings.Repeat("a", 10*int(testBodyLimit)), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var (
				data    []byte
				readErr error
			)
			r := gin.New()
			r.POST("/upload", BodyLimit(testBodyLimit), func(c *gin.Context) {
				data, readErr = io.ReadAll(c.Request.Body)
				c.Status(http.StatusNoContent)
			})

			serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/upload", strings.NewReader(tt.body)))

			if !tt.wantErr {
				require.NoError(t, readErr)
				assert.Equal(t, tt.body, string(data))
				return
			}
			var tooLarge *http.MaxBytesError
			require.ErrorAs(t, readErr, &tooLarge)
			assert.Equal(t, testBodyLimit, tooLarge.Limit)
		})
	}
}

func TestBodyLimit_LeavesAnAbsentBodyUntouched(t *testing.T) {
	t.Parallel()
	var seen io.ReadCloser
	r := gin.New()
	r.GET("/ping", BodyLimit(testBodyLimit), func(c *gin.Context) {
		seen = c.Request.Body
		okHandler(c)
	})

	rec := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ping", http.NoBody))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.NoBody, seen, "no reader is wrapped when there is nothing to read")
}

func TestBodyLimit_JSONBindingReportsMaxBytesError(t *testing.T) {
	t.Parallel()
	var bindErr error
	r := gin.New()
	r.POST("/json", BodyLimit(testBodyLimit), func(c *gin.Context) {
		var payload struct {
			Name string `json:"name"`
		}
		bindErr = c.ShouldBindJSON(&payload)
		c.Status(http.StatusNoContent)
	})
	body := `{"name":"` + strings.Repeat("x", int(testBodyLimit)) + `"}`

	serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/json", strings.NewReader(body)))

	var tooLarge *http.MaxBytesError
	require.ErrorAs(t, bindErr, &tooLarge, "handlers map this error to 413")
	assert.Equal(t, testBodyLimit, tooLarge.Limit)
}
