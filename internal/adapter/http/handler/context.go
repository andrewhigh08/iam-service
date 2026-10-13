package handler

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// Keys under which the auth middleware stores the caller's identity in the gin context.
const (
	ContextKeyUserID    = "user_id"
	ContextKeySessionID = "session_id"
)

const (
	bearerScheme = "Bearer"
	// maxUserAgentBytes bounds the User-Agent kept with sessions and audit entries; headers are
	// otherwise limited only by the server's header size limit.
	maxUserAgentBytes = 512
)

func clientMeta(c *gin.Context) domain.ClientMeta {
	return domain.ClientMeta{IP: c.ClientIP(), UserAgent: sanitizeUserAgent(c.GetHeader("User-Agent"))}
}

// sanitizeUserAgent makes a User-Agent header safe to store and log: invalid UTF-8 is
// replaced by U+FFFD, control characters are dropped and the rest is cut to maxUserAgentBytes.
func sanitizeUserAgent(ua string) string {
	ua = strings.ToValidUTF8(ua, "�")
	ua = strings.Map(dropControl, ua)
	return truncateUTF8(ua, maxUserAgentBytes)
}

// dropControl maps control characters to -1, which strings.Map removes.
func dropControl(r rune) rune {
	if unicode.IsControl(r) {
		return -1
	}
	return r
}

// truncateUTF8 cuts s to at most limit bytes without splitting a multi-byte character.
func truncateUTF8(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

func actorFrom(c *gin.Context) domain.Actor {
	return domain.Actor{UserID: c.GetInt64(ContextKeyUserID), ClientMeta: clientMeta(c)}
}

func bearerToken(c *gin.Context) (string, bool) {
	scheme, token, found := strings.Cut(c.GetHeader("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
