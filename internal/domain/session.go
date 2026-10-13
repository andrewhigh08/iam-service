package domain

import "time"

// SessionIDLength is the number of leading hex characters of the refresh-token digest that
// form a session id (sid).
const SessionIDLength = 16

// ClientMeta identifies the client that performed a request.
type ClientMeta struct {
	IP        string
	UserAgent string
}

// Actor is the authenticated user performing an action, with the client it acts from.
type Actor struct {
	UserID int64
	ClientMeta
}

// Session is a live refresh-token session.
// ID is the short session identifier (sid) carried by access tokens. TokenHash is the full
// SHA-256 hex digest of the refresh token under which the session is stored; it is never
// exposed to clients. AccessJTI and AccessExpiresAt describe the access token issued with the
// session, so that revoking the session can blacklist it. Current marks the session that made
// the current request.
type Session struct {
	ID              string
	TokenHash       string
	UserID          int64
	CreatedAt       time.Time
	ExpiresAt       time.Time
	IP              string
	UserAgent       string
	AccessJTI       string
	AccessExpiresAt time.Time
	Current         bool
}
