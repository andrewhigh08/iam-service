package integration

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Roles and passwords the tests use when they create accounts.
const (
	roleAdmin   = "admin"
	roleAnalyst = "analyst"
	roleViewer  = "viewer"

	initialPassword = "In1tial!Secret"
	wrongPassword   = "Wr0ng!Password"
)

// apiClient sends JSON requests to a booted service.
type apiClient struct {
	baseURL string
	http    *http.Client
}

// newClient returns a client for the shared server, skipping the test when there is none.
func newClient(t *testing.T) *apiClient {
	t.Helper()
	s := env(t)
	return &apiClient{baseURL: s.server.URL, http: s.server.Client()}
}

// rawBody is a request body sent verbatim instead of being encoded as JSON.
type rawBody string

// envelope is the JSON envelope every endpoint of the API answers with.
type envelope struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   *errorBody      `json:"error"`
	Meta    *metaBody       `json:"meta"`
}

// errorBody is the error part of the envelope.
type errorBody struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details"`
}

// metaBody is the pagination part of the envelope.
type metaBody struct {
	Page       int   `json:"page"`
	PageSize   int   `json:"page_size"`
	Total      int64 `json:"total"`
	TotalPages int   `json:"total_pages"`
}

// apiResponse is one answer of the service: status, headers, raw body and, when the body is
// JSON, the decoded envelope.
type apiResponse struct {
	Status int
	Header http.Header
	Body   []byte
	envelope
}

// do sends method path with body encoded as JSON (nil for no body, rawBody to send bytes as
// they are) and token as the bearer access token (empty for none).
func (c *apiClient) do(t *testing.T, method, path string, body any, token string) apiResponse {
	t.Helper()
	req := c.newRequest(t, method, path, body)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return c.send(t, req)
}

// newRequest builds a request for path with body encoded as JSON, or sent verbatim for a rawBody.
func (c *apiClient) newRequest(t *testing.T, method, path string, body any) *http.Request {
	t.Helper()
	var reader io.Reader = http.NoBody
	switch b := body.(type) {
	case nil:
	case rawBody:
		reader = strings.NewReader(string(b))
	default:
		encoded, err := json.Marshal(b)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(t.Context(), method, c.baseURL+path, reader)
	require.NoError(t, err)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// send executes req, reads the whole body and decodes the envelope of a JSON answer.
func (c *apiClient) send(t *testing.T, req *http.Request) apiResponse {
	t.Helper()
	resp, err := c.http.Do(req)
	require.NoErrorf(t, err, "%s %s", req.Method, req.URL.Path)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	out := apiResponse{Status: resp.StatusCode, Header: resp.Header, Body: raw}
	if strings.HasPrefix(resp.Header.Get("Content-Type"), "application/json") {
		require.NoErrorf(t, json.Unmarshal(raw, &out.envelope), "%s %s: body %q", req.Method, req.URL.Path, raw)
	}
	return out
}

// decode unmarshals the data field of the envelope into dst.
func (r apiResponse) decode(t *testing.T, dst any) {
	t.Helper()
	require.NotEmptyf(t, r.Data, "response carries no data: %s", r.Body)
	require.NoErrorf(t, json.Unmarshal(r.Data, dst), "decode data %s", r.Data)
}

// requireStatus fails the test unless resp has the expected status, showing the body otherwise.
func requireStatus(t *testing.T, resp apiResponse, status int) {
	t.Helper()
	require.Equalf(t, status, resp.Status, "unexpected status, body: %s", resp.Body)
}

// requireError checks that resp is a failed envelope with the given status and error code and
// returns its error body for further assertions.
func requireError(t *testing.T, resp apiResponse, status int, code string) errorBody {
	t.Helper()
	requireStatus(t, resp, status)
	require.NotNilf(t, resp.Error, "no error in body: %s", resp.Body)
	assert.False(t, resp.Success)
	assert.Equal(t, code, resp.Error.Code)
	assert.Empty(t, resp.Data)
	return *resp.Error
}

// fieldRule returns the binding rule reported for field in the error details, or "".
func fieldRule(e errorBody, field string) string {
	fields, _ := e.Details["fields"].(map[string]any)
	rule, _ := fields[field].(string)
	return rule
}

// tokenPair is the token part of the login, refresh and change-password answers.
type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

// loginData is the data of POST /auth/login.
type loginData struct {
	tokenPair
	User                  *userInfo `json:"user"`
	RequirePasswordChange bool      `json:"require_password_change"`
	Reason                string    `json:"reason"`
}

// userInfo identifies the logged-in user.
type userInfo struct {
	ID    int64    `json:"id"`
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// userData is a user as the users endpoints render it.
type userData struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	FullName  string    `json:"full_name"`
	IsBlocked bool      `json:"is_blocked"`
	CreatedAt time.Time `json:"created_at"`
}

// usersData is the data of GET /api/v1/users.
type usersData struct {
	Users []userData `json:"users"`
}

// sessionData is one session as GET /api/v1/sessions renders it.
type sessionData struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip"`
	UserAgent string    `json:"user_agent"`
	Current   bool      `json:"current"`
}

// sessionsData is the data of GET /api/v1/sessions.
type sessionsData struct {
	Sessions []sessionData `json:"sessions"`
	Total    int           `json:"total"`
}

// auditEntryData is one entry as GET /api/v1/users/:id/audit renders it.
type auditEntryData struct {
	ID        int64          `json:"id"`
	ActorID   int64          `json:"actor_id"`
	Action    string         `json:"action"`
	Details   map[string]any `json:"details"`
	IP        string         `json:"ip"`
	UserAgent string         `json:"user_agent"`
	CreatedAt time.Time      `json:"created_at"`
}

// auditEntriesData is the data of GET /api/v1/users/:id/audit.
type auditEntriesData struct {
	Entries []auditEntryData `json:"entries"`
	Total   int              `json:"total"`
}

// messageData is the data of the endpoints that only confirm an action.
type messageData struct {
	Message string `json:"message"`
}

// createUserRequest is the body of POST /api/v1/users.
type createUserRequest struct {
	Email             string `json:"email"`
	Password          string `json:"password"`
	FullName          string `json:"full_name"`
	Role              string `json:"role"`
	PasswordTemporary bool   `json:"password_temporary"`
}

// account is a user a test created, with its current password.
type account struct {
	ID       int64
	Email    string
	Password string
}

// accessClaims are the claims of an access token the tests look at.
type accessClaims struct {
	UserID    int64    `json:"uid"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	SessionID string   `json:"sid"`
	jwt.RegisteredClaims
}

// parseClaims decodes the claims of an access token without verifying it.
func parseClaims(t *testing.T, token string) accessClaims {
	t.Helper()
	var claims accessClaims
	_, _, err := jwt.NewParser().ParseUnverified(token, &claims)
	require.NoError(t, err)
	return claims
}

// login posts the credentials and returns the raw answer.
func (c *apiClient) login(t *testing.T, email, password string) apiResponse {
	t.Helper()
	return c.do(t, http.MethodPost, "/auth/login", map[string]string{"email": email, "password": password}, "")
}

// mustLogin logs in and requires a token pair in the answer.
func (c *apiClient) mustLogin(t *testing.T, email, password string) loginData {
	t.Helper()
	resp := c.login(t, email, password)
	requireStatus(t, resp, http.StatusOK)
	var data loginData
	resp.decode(t, &data)
	require.NotEmptyf(t, data.AccessToken, "login returned no access token: %s", resp.Body)
	require.NotEmpty(t, data.RefreshToken)
	return data
}

// adminToken logs the seeded administrator in and returns the access token.
func (c *apiClient) adminToken(t *testing.T) string {
	t.Helper()
	return c.mustLogin(t, adminEmail, adminPassword).AccessToken
}

// refresh posts refreshToken to /auth/refresh.
func (c *apiClient) refresh(t *testing.T, refreshToken string) apiResponse {
	t.Helper()
	return c.do(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": refreshToken}, "")
}

// sessions lists the sessions of the caller identified by token.
func (c *apiClient) sessions(t *testing.T, token string) apiResponse {
	t.Helper()
	return c.do(t, http.MethodGet, "/api/v1/sessions", nil, token)
}

// createUser posts req to /api/v1/users as the caller identified by token.
func (c *apiClient) createUser(t *testing.T, token string, req createUserRequest) apiResponse {
	t.Helper()
	return c.do(t, http.MethodPost, "/api/v1/users", req, token)
}

// mustCreateUser creates a user with role and the initial password, permanent or temporary,
// as the administrator identified by adminToken, and returns the account.
func (c *apiClient) mustCreateUser(t *testing.T, adminToken, role string, temporary bool) account {
	t.Helper()
	return c.mustCreateUserWithEmail(t, adminToken, uniqueEmail(t), role, temporary)
}

// mustCreateUserWithEmail is mustCreateUser for a caller-chosen address.
func (c *apiClient) mustCreateUserWithEmail(t *testing.T, adminToken, email, role string, temporary bool) account {
	t.Helper()
	acc := account{Email: email, Password: initialPassword}
	resp := c.createUser(t, adminToken, createUserRequest{
		Email:             acc.Email,
		Password:          acc.Password,
		FullName:          "Integration " + role,
		Role:              role,
		PasswordTemporary: temporary,
	})
	requireStatus(t, resp, http.StatusCreated)
	var created userData
	resp.decode(t, &created)
	require.Positive(t, created.ID)
	acc.ID = created.ID
	return acc
}

// getUser fetches user id as the caller identified by token and requires success.
func (c *apiClient) getUser(t *testing.T, token string, id int64) userData {
	t.Helper()
	resp := c.do(t, http.MethodGet, userPath(id, ""), nil, token)
	requireStatus(t, resp, http.StatusOK)
	var user userData
	resp.decode(t, &user)
	return user
}

// userPath returns the path of the user endpoint for id, with an optional action suffix such
// as "/block".
func userPath(id int64, action string) string {
	return "/api/v1/users/" + strconv.FormatInt(id, 10) + action
}

// emailPrefix returns the part every address created by the test starts with: the test name
// reduced to lower-case letters, digits and dashes.
func emailPrefix(t *testing.T) string {
	t.Helper()
	prefix := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, strings.ToLower(t.Name()))
	if len(prefix) > 40 {
		prefix = prefix[:40]
	}
	return prefix
}

// uniquePrefix returns a prefix no other test, and no earlier run against the same database,
// has used: the test name followed by a random suffix.
func uniquePrefix(t *testing.T) string {
	t.Helper()
	return emailPrefix(t) + "-" + strings.ToLower(rand.Text()[:8])
}

// uniqueEmail returns an address built on uniquePrefix.
func uniqueEmail(t *testing.T) string {
	t.Helper()
	return uniquePrefix(t) + "@example.com"
}
