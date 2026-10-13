package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// requestIDRouter serves GET /ping behind RequestID and reports the ids the handler observed.
func requestIDRouter(ginID, ctxID *string) *gin.Engine {
	r := gin.New()
	r.Use(RequestID())
	r.GET("/ping", func(c *gin.Context) {
		*ginID = c.GetString(RequestIDKey)
		*ctxID = logger.RequestIDFromContext(c.Request.Context())
		okHandler(c)
	})
	return r
}

func TestRequestID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		supplied string
		accepted bool
	}{
		{"generates an id when the header is missing", "", false},
		{"accepts letters, digits, dots, underscores and dashes", "req-123.abc_DEF", true},
		{"accepts a 128 character id", strings.Repeat("a", 128), true},
		{"rejects a 129 character id", strings.Repeat("a", 129), false},
		{"rejects spaces", "abc def", false},
		{"rejects other punctuation", "abc;def", false},
		{"rejects non-ASCII characters", "réquest-1", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var ginID, ctxID string
			r := requestIDRouter(&ginID, &ctxID)
			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ping", http.NoBody)
			if tt.supplied != "" {
				req.Header.Set(RequestIDHeader, tt.supplied)
			}

			rec := serve(r, req)

			require.Equal(t, http.StatusOK, rec.Code)
			echoed := rec.Header().Get(RequestIDHeader)
			if tt.accepted {
				assert.Equal(t, tt.supplied, echoed)
			} else {
				assert.NotEqual(t, tt.supplied, echoed)
				_, err := uuid.Parse(echoed)
				require.NoError(t, err, "a rejected or missing id is replaced by a UUID")
			}
			assert.Equal(t, echoed, ginID, "the gin context holds the echoed id")
			assert.Equal(t, echoed, ctxID, "the request context holds the echoed id")
		})
	}
}

func TestRequestID_GeneratedIDsAreUnique(t *testing.T) {
	t.Parallel()
	var ginID, ctxID string
	r := requestIDRouter(&ginID, &ctxID)

	first := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ping", http.NoBody))
	second := serve(r, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/ping", http.NoBody))

	assert.NotEqual(t, first.Header().Get(RequestIDHeader), second.Header().Get(RequestIDHeader))
}
