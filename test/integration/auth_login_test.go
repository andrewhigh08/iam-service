package integration

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// jsonWebKey is one RSA key of the JWKS document.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func TestAdminLoginIssuesTokensVerifiableWithJWKS(t *testing.T) {
	t.Parallel()
	c := newClient(t)

	resp := c.login(t, adminEmail, adminPassword)
	requireStatus(t, resp, http.StatusOK)
	assert.True(t, resp.Success)
	assert.Nil(t, resp.Error)
	var login loginData
	resp.decode(t, &login)
	assert.Equal(t, "Bearer", login.TokenType)
	assert.Equal(t, int64(accessTTL/time.Second), login.ExpiresIn)
	assert.Len(t, login.RefreshToken, 64)
	assert.False(t, login.RequirePasswordChange)
	assert.Empty(t, login.Reason)
	require.NotNil(t, login.User)
	assert.Positive(t, login.User.ID)
	assert.Equal(t, adminEmail, login.User.Email)
	assert.Equal(t, []string{roleAdmin}, login.User.Roles)

	jwks := c.do(t, http.MethodGet, "/.well-known/jwks.json", nil, "")
	requireStatus(t, jwks, http.StatusOK)
	var keySet struct {
		Keys []jsonWebKey `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(jwks.Body, &keySet))
	require.Len(t, keySet.Keys, 1)
	key := keySet.Keys[0]
	assert.Equal(t, "RSA", key.Kty)
	assert.Equal(t, "sig", key.Use)
	assert.Equal(t, "RS256", key.Alg)
	assert.Len(t, key.Kid, 16)

	claims := verifyWithJWK(t, login.AccessToken, key)
	assert.Equal(t, strconv.FormatInt(login.User.ID, 10), claims.Subject)
	assert.Equal(t, tokenIssuer, claims.Issuer)
	assert.Equal(t, login.User.ID, claims.UserID)
	assert.Equal(t, adminEmail, claims.Email)
	assert.Equal(t, []string{roleAdmin}, claims.Roles)
	assert.Len(t, claims.SessionID, 16)
	assert.Len(t, claims.ID, 32)
	require.NotNil(t, claims.IssuedAt)
	require.NotNil(t, claims.ExpiresAt)
	assert.Equal(t, accessTTL, claims.ExpiresAt.Sub(claims.IssuedAt.Time))
}

// verifyWithJWK checks the signature of token against the published RSA key and returns its claims.
func verifyWithJWK(t *testing.T, token string, key jsonWebKey) accessClaims {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(key.N)
	require.NoError(t, err)
	e, err := base64.RawURLEncoding.DecodeString(key.E)
	require.NoError(t, err)
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}

	var claims accessClaims
	var kid any
	parsed, err := jwt.ParseWithClaims(token, &claims, func(tok *jwt.Token) (any, error) {
		kid = tok.Header["kid"]
		return pub, nil
	}, jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}), jwt.WithIssuer(tokenIssuer), jwt.WithExpirationRequired())
	require.NoError(t, err)
	require.True(t, parsed.Valid)
	assert.Equal(t, key.Kid, kid)
	return claims
}

func TestLoginRejectsBadCredentials(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, false)

	tests := []struct {
		name    string
		body    any
		status  int
		code    string
		message string
		field   string
		rule    string
	}{
		{
			name:    "wrong password",
			body:    map[string]string{"email": acc.Email, "password": wrongPassword},
			status:  http.StatusUnauthorized,
			code:    "UNAUTHORIZED",
			message: "invalid credentials",
		},
		{
			name:    "unknown account gets the same answer",
			body:    map[string]string{"email": "unknown-" + acc.Email, "password": acc.Password},
			status:  http.StatusUnauthorized,
			code:    "UNAUTHORIZED",
			message: "invalid credentials",
		},
		{
			name:    "missing password",
			body:    map[string]string{"email": acc.Email},
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "invalid request body",
			field:   "password",
			rule:    "required",
		},
		{
			name:    "malformed email",
			body:    map[string]string{"email": "not-an-address", "password": acc.Password},
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "invalid request body",
			field:   "email",
			rule:    "email",
		},
		{
			name:    "body is not JSON",
			body:    rawBody("{"),
			status:  http.StatusBadRequest,
			code:    "VALIDATION_ERROR",
			message: "invalid request body",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			errBody := requireError(t, c.do(t, http.MethodPost, "/auth/login", tc.body, ""), tc.status, tc.code)
			assert.Equal(t, tc.message, errBody.Message)
			if tc.field != "" {
				assert.Equal(t, tc.rule, fieldRule(errBody, tc.field))
			}
		})
	}
}

func TestTemporaryPasswordMustBeChangedBeforeTokensAreIssued(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	acc := c.mustCreateUser(t, c.adminToken(t), roleViewer, true)

	resp := c.login(t, acc.Email, acc.Password)
	requireStatus(t, resp, http.StatusOK)
	var login loginData
	resp.decode(t, &login)
	assert.True(t, login.RequirePasswordChange)
	assert.Equal(t, "temporary_password", login.Reason)
	assert.Empty(t, login.AccessToken)
	assert.Empty(t, login.RefreshToken)
	assert.Nil(t, login.User)

	const newPassword = "Perm4nent!Secret"
	change := func(oldPassword, replacement string) apiResponse {
		return c.do(t, http.MethodPost, "/auth/change-password", map[string]string{
			"email": acc.Email, "old_password": oldPassword, "new_password": replacement,
		}, "")
	}

	weak := requireError(t, change(acc.Password, "weak"), http.StatusBadRequest, "VALIDATION_ERROR")
	assert.Equal(t, "password does not meet the policy", weak.Message)
	assert.NotEmpty(t, weak.Details["errors"])

	rejected := requireError(t, change(wrongPassword, newPassword), http.StatusUnauthorized, "UNAUTHORIZED")
	assert.Equal(t, "invalid credentials", rejected.Message)

	changed := change(acc.Password, newPassword)
	requireStatus(t, changed, http.StatusOK)
	var pair tokenPair
	changed.decode(t, &pair)
	assert.Equal(t, "Bearer", pair.TokenType)
	assert.Equal(t, int64(accessTTL/time.Second), pair.ExpiresIn)
	assert.Len(t, pair.RefreshToken, 64)
	assert.Equal(t, []string{roleViewer}, parseClaims(t, pair.AccessToken).Roles)
	requireStatus(t, c.sessions(t, pair.AccessToken), http.StatusOK)

	// The old password is gone and the new one logs in without a further change.
	requireError(t, c.login(t, acc.Email, acc.Password), http.StatusUnauthorized, "UNAUTHORIZED")
	second := c.mustLogin(t, acc.Email, newPassword)
	assert.False(t, second.RequirePasswordChange)
	require.NotNil(t, second.User)
	assert.Equal(t, []string{roleViewer}, second.User.Roles)

	notRequired := requireError(t, change(newPassword, "An0ther!Secret"), http.StatusBadRequest, "BAD_REQUEST")
	assert.Equal(t, "password change not required", notRequired.Message)
}

func TestProtectedEndpointsRejectInvalidTokens(t *testing.T) {
	t.Parallel()
	c := newClient(t)
	valid := c.adminToken(t)
	claims := parseClaims(t, valid)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	forged, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(otherKey)
	require.NoError(t, err)
	symmetric, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte("not-the-key"))
	require.NoError(t, err)

	tests := []struct {
		name    string
		header  string
		message string
	}{
		{name: "missing header", header: "", message: "missing authorization header"},
		{name: "wrong scheme", header: "Basic " + valid, message: "invalid authorization header format"},
		{name: "bearer without token", header: "Bearer", message: "invalid authorization header format"},
		{name: "garbage token", header: "Bearer not.a.jwt", message: "invalid or expired token"},
		{name: "token signed with another key", header: "Bearer " + forged, message: "invalid or expired token"},
		{name: "token with a symmetric algorithm", header: "Bearer " + symmetric, message: "invalid or expired token"},
		{name: "tampered payload", header: "Bearer " + tamper(t, valid, claims), message: "invalid or expired token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req := c.newRequest(t, http.MethodGet, "/api/v1/sessions", nil)
			if tc.header != "" {
				req.Header.Set("Authorization", tc.header)
			}
			errBody := requireError(t, c.send(t, req), http.StatusUnauthorized, "UNAUTHORIZED")
			assert.Equal(t, tc.message, errBody.Message)
		})
	}
	requireStatus(t, c.sessions(t, valid), http.StatusOK)
}

// tamper re-encodes the payload of token with another user id, keeping the original signature.
func tamper(t *testing.T, token string, claims accessClaims) string {
	t.Helper()
	claims.UserID++
	payload, err := json.Marshal(claims)
	require.NoError(t, err)
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3)
	parts[1] = base64.RawURLEncoding.EncodeToString(payload)
	return strings.Join(parts, ".")
}
