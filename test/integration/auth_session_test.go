package integration

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRefreshRotatesTheSession(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)
	first := c.mustLogin(t, acc.Email, acc.Password)

	rotated := c.refresh(t, first.RefreshToken)
	requireStatus(t, rotated, http.StatusOK)
	var second tokenPair
	rotated.decode(t, &second)
	assert.Equal(t, "Bearer", second.TokenType)
	assert.Equal(t, int64(accessTTL/time.Second), second.ExpiresIn)
	assert.NotEqual(t, first.RefreshToken, second.RefreshToken)
	assert.NotEqual(t, first.AccessToken, second.AccessToken)
	newSID := parseClaims(t, second.AccessToken).SessionID
	assert.NotEqual(t, parseClaims(t, first.AccessToken).SessionID, newSID)

	// Only the rotated session exists; it keeps the original start time under the new sid.
	list := c.sessions(t, second.AccessToken)
	requireStatus(t, list, http.StatusOK)
	var sessions sessionsData
	list.decode(t, &sessions)
	require.Len(t, sessions.Sessions, 1)
	assert.Equal(t, newSID, sessions.Sessions[0].ID)
	assert.True(t, sessions.Sessions[0].Current)
	assert.GreaterOrEqual(t, sessions.Sessions[0].ExpiresAt.Sub(sessions.Sessions[0].CreatedAt), refreshTTL)

	// The rotated access token is blacklisted while the new pair keeps working.
	requireError(t, c.sessions(t, first.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
	rotatedAgain := c.refresh(t, second.RefreshToken)
	requireStatus(t, rotatedAgain, http.StatusOK)
	var third tokenPair
	rotatedAgain.decode(t, &third)
	requireStatus(t, c.sessions(t, third.AccessToken), http.StatusOK)

	// Replaying a consumed refresh token is treated as theft: it is rejected and every session
	// of the user is revoked, including the one holding the successor.
	replayed := requireError(t, c.refresh(t, first.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid or expired refresh token", replayed.Message)
	requireError(t, c.refresh(t, third.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	requireError(t, c.sessions(t, third.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")

	requireError(t, c.refresh(t, "not-a-refresh-token"), http.StatusUnauthorized, "UNAUTHORIZED")
	requireError(t, c.do(t, http.MethodPost, "/auth/refresh", map[string]string{}, ""), http.StatusBadRequest, "VALIDATION_ERROR")
}

func TestSessionsListMarksCurrentAndRevokesOthers(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)
	first := c.mustLogin(t, acc.Email, acc.Password)
	second := c.mustLogin(t, acc.Email, acc.Password)

	list := c.sessions(t, second.AccessToken)
	requireStatus(t, list, http.StatusOK)
	var data sessionsData
	list.decode(t, &data)
	assert.Equal(t, 2, data.Total)
	require.Len(t, data.Sessions, 2)

	bySID := make(map[string]sessionData, len(data.Sessions))
	for _, s := range data.Sessions {
		bySID[s.ID] = s
		assert.Equal(t, "127.0.0.1", s.IP)
		assert.Equal(t, "Go-http-client/1.1", s.UserAgent)
		assert.Equal(t, time.UTC, s.CreatedAt.Location())
		assert.WithinDuration(t, s.CreatedAt.Add(refreshTTL), s.ExpiresAt, time.Minute)
	}
	currentSID := parseClaims(t, second.AccessToken).SessionID
	otherSID := parseClaims(t, first.AccessToken).SessionID
	require.Contains(t, bySID, currentSID)
	require.Contains(t, bySID, otherSID)
	assert.True(t, bySID[currentSID].Current, "the caller's session is not marked current")
	assert.False(t, bySID[otherSID].Current)

	// Revoking the other session kills both of its tokens and leaves the caller's alone.
	revoked := c.do(t, http.MethodDelete, "/api/v1/sessions/"+otherSID, nil, second.AccessToken)
	requireStatus(t, revoked, http.StatusOK)
	var msg messageData
	revoked.decode(t, &msg)
	assert.Equal(t, "session revoked", msg.Message)
	requireError(t, c.refresh(t, first.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	denied := requireError(t, c.sessions(t, first.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid or expired token", denied.Message)

	list = c.sessions(t, second.AccessToken)
	requireStatus(t, list, http.StatusOK)
	list.decode(t, &data)
	require.Len(t, data.Sessions, 1)
	assert.Equal(t, 1, data.Total)
	assert.Equal(t, currentSID, data.Sessions[0].ID)
	assert.True(t, data.Sessions[0].Current)

	// A session that is gone, or belongs to someone else, is not found.
	requireError(t, c.do(t, http.MethodDelete, "/api/v1/sessions/"+otherSID, nil, second.AccessToken), http.StatusNotFound, "NOT_FOUND")
	adminSID := parseClaims(t, c.adminToken(t)).SessionID
	requireError(t, c.do(t, http.MethodDelete, "/api/v1/sessions/"+adminSID, nil, second.AccessToken), http.StatusNotFound, "NOT_FOUND")
}

func TestLogoutAllRevokesEverySessionAndToken(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)
	first := c.mustLogin(t, acc.Email, acc.Password)
	second := c.mustLogin(t, acc.Email, acc.Password)

	resp := c.do(t, http.MethodPost, "/api/v1/logout-all", nil, first.AccessToken)
	requireStatus(t, resp, http.StatusOK)
	var msg messageData
	resp.decode(t, &msg)
	assert.Equal(t, "logged out from all sessions", msg.Message)

	for _, pair := range []tokenPair{first.tokenPair, second.tokenPair} {
		denied := requireError(t, c.sessions(t, pair.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
		assert.Equal(t, "invalid or expired token", denied.Message)
		requireError(t, c.refresh(t, pair.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	}

	// Logging in again right away, even within the revocation second, yields a working session.
	third := c.mustLogin(t, acc.Email, acc.Password)
	list := c.sessions(t, third.AccessToken)
	requireStatus(t, list, http.StatusOK)
	var data sessionsData
	list.decode(t, &data)
	assert.Equal(t, 1, data.Total)
}

func TestLogoutRevokesBothTokens(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)

	// The access token travels in the Authorization header.
	pair := c.mustLogin(t, acc.Email, acc.Password)
	requireStatus(t, c.sessions(t, pair.AccessToken), http.StatusOK)
	body := map[string]string{"refresh_token": pair.RefreshToken}
	resp := c.do(t, http.MethodPost, "/auth/logout", body, pair.AccessToken)
	requireStatus(t, resp, http.StatusOK)
	var msg messageData
	resp.decode(t, &msg)
	assert.Equal(t, "logged out", msg.Message)
	denied := requireError(t, c.sessions(t, pair.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid or expired token", denied.Message)
	requireError(t, c.refresh(t, pair.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")

	// Logging out again is harmless, and a logout needs a refresh token.
	requireStatus(t, c.do(t, http.MethodPost, "/auth/logout", body, pair.AccessToken), http.StatusOK)
	requireError(t, c.do(t, http.MethodPost, "/auth/logout", map[string]string{}, ""), http.StatusBadRequest, "VALIDATION_ERROR")

	// The access token may be given in the body instead.
	pair = c.mustLogin(t, acc.Email, acc.Password)
	inBody := map[string]string{"refresh_token": pair.RefreshToken, "access_token": pair.AccessToken}
	requireStatus(t, c.do(t, http.MethodPost, "/auth/logout", inBody, ""), http.StatusOK)
	requireError(t, c.sessions(t, pair.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
	requireError(t, c.refresh(t, pair.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
}

func TestAuthenticatedPasswordChangeRevokesOtherSessions(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)
	first := c.mustLogin(t, acc.Email, acc.Password)
	second := c.mustLogin(t, acc.Email, acc.Password)

	const newPassword = "Ch4nged!Secret"
	change := func(token, oldPassword, replacement string) apiResponse {
		return c.do(t, http.MethodPost, "/api/v1/change-password", map[string]string{
			"old_password": oldPassword, "new_password": replacement,
		}, token)
	}

	wrongOld := requireError(t, change(first.AccessToken, wrongPassword, newPassword), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid old password", wrongOld.Message)
	same := requireError(t, change(first.AccessToken, acc.Password, acc.Password), http.StatusBadRequest, "VALIDATION_ERROR")
	assert.Equal(t, []any{"new password must differ from the current one"}, same.Details["errors"])
	requireError(t, change("", acc.Password, newPassword), http.StatusUnauthorized, "UNAUTHORIZED")

	changed := change(first.AccessToken, acc.Password, newPassword)
	requireStatus(t, changed, http.StatusOK)
	var fresh tokenPair
	changed.decode(t, &fresh)
	require.NotEmpty(t, fresh.AccessToken)

	// Every earlier session is gone, including the caller's; the fresh pair works at once.
	for _, pair := range []tokenPair{first.tokenPair, second.tokenPair} {
		requireError(t, c.sessions(t, pair.AccessToken), http.StatusUnauthorized, "UNAUTHORIZED")
		requireError(t, c.refresh(t, pair.RefreshToken), http.StatusUnauthorized, "UNAUTHORIZED")
	}
	list := c.sessions(t, fresh.AccessToken)
	requireStatus(t, list, http.StatusOK)
	var data sessionsData
	list.decode(t, &data)
	assert.Equal(t, 1, data.Total)
	requireStatus(t, c.refresh(t, fresh.RefreshToken), http.StatusOK)

	requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED")
	c.mustLogin(t, acc.Email, newPassword)
}
