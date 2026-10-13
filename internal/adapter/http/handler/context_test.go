package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

func TestBearerToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name          string
		authorization string
		wantToken     string
		wantOK        bool
	}{
		{"missing header", "", "", false},
		{"bearer token", "Bearer abc.def.ghi", "abc.def.ghi", true},
		{"lower-case scheme", "bearer abc", "abc", true},
		{"surrounding spaces are trimmed", "Bearer   abc  ", "abc", true},
		{"scheme only", "Bearer", "", false},
		{"scheme with blank token", "Bearer   ", "", false},
		{"basic scheme", "Basic abc", "", false},
		{"token without scheme", "abc", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			c, _ := gin.CreateTestContext(httptest.NewRecorder())
			c.Request = newRequest(t, http.MethodGet, "/", nil)
			if tt.authorization != "" {
				c.Request.Header.Set("Authorization", tt.authorization)
			}

			token, ok := bearerToken(c)

			assert.Equal(t, tt.wantOK, ok)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

func TestClientMeta(t *testing.T) {
	t.Parallel()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = newRequest(t, http.MethodGet, "/", nil)

	assert.Equal(t, testMeta, clientMeta(c))
}

func TestClientMeta_BoundsTheUserAgent(t *testing.T) {
	t.Parallel()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = newRequest(t, http.MethodGet, "/", nil)
	long := strings.Repeat("a", maxUserAgentBytes-1) + strings.Repeat("\u00e9", 10)
	c.Request.Header.Set("User-Agent", long)

	ua := clientMeta(c).UserAgent

	assert.LessOrEqual(t, len(ua), maxUserAgentBytes)
	assert.True(t, utf8.ValidString(ua), "the cut never splits a character")
	assert.Equal(t, strings.Repeat("a", maxUserAgentBytes-1), ua)
}

func TestTruncateUTF8(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		in    string
		limit int
		want  string
	}{
		{"short string is untouched", "abc", 5, "abc"},
		{"exact limit is untouched", "abcde", 5, "abcde"},
		{"ascii is cut at the limit", "abcdef", 3, "abc"},
		{"multi-byte character is not split", "ab\u00e9", 3, "ab"},
		{"zero limit yields nothing", "abc", 0, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, truncateUTF8(tt.in, tt.limit))
		})
	}
}

func TestActorFrom(t *testing.T) {
	t.Parallel()

	t.Run("authenticated caller", func(t *testing.T) {
		t.Parallel()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = newRequest(t, http.MethodGet, "/", nil)
		c.Set(ContextKeyUserID, testUserID)

		assert.Equal(t, testActor, actorFrom(c))
	})

	t.Run("anonymous caller", func(t *testing.T) {
		t.Parallel()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = newRequest(t, http.MethodGet, "/", nil)

		assert.Equal(t, domain.Actor{ClientMeta: testMeta}, actorFrom(c))
	})
}
