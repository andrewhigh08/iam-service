package handler

import (
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// Keys under which the auth middleware stores the caller's identity in the gin context.
const (
	ContextKeyUserID    = "user_id"
	ContextKeySessionID = "session_id"
	ContextKeyEmail     = "email"
	ContextKeyRoles     = "roles"
)

const (
	// bearerScheme is the Authorization scheme that carries access tokens.
	bearerScheme = "Bearer"
	// maxUserAgentBytes bounds the User-Agent kept with sessions and audit entries; headers are
	// otherwise limited only by the server's header size limit.
	maxUserAgentBytes = 512
)

// clientMeta describes the client behind the request.
func clientMeta(c *gin.Context) domain.ClientMeta {
	return domain.ClientMeta{IP: c.ClientIP(), UserAgent: truncateUTF8(c.GetHeader("User-Agent"), maxUserAgentBytes)}
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

// actorFrom identifies the authenticated caller together with the client it acts from.
func actorFrom(c *gin.Context) domain.Actor {
	return domain.Actor{UserID: c.GetInt64(ContextKeyUserID), ClientMeta: clientMeta(c)}
}

// bearerToken extracts the token of a "Bearer <token>" Authorization header.
// It reports false when the header is absent or malformed.
func bearerToken(c *gin.Context) (string, bool) {
	scheme, token, found := strings.Cut(c.GetHeader("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}
