package service

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const testSID = "0123456789abcdef"

// craftToken signs claims outside the service with method and key.
func craftToken(t *testing.T, method jwt.SigningMethod, key any, claims port.Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(method, claims).SignedString(key)
	require.NoError(t, err)
	return token
}

func validClaims(user *domain.User, at time.Time) port.Claims {
	return port.Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Roles:     []string{domain.RoleViewer},
		SessionID: testSID,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "00112233445566778899aabbccddeeff",
			Issuer:    defaultIssuer,
			Subject:   "42",
			IssuedAt:  jwt.NewNumericDate(at),
			ExpiresAt: jwt.NewNumericDate(at.Add(testAccessTTL)),
		},
	}
}

func TestAuthService_ValidateAccessToken_AcceptsIssuedToken(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	token := f.issuedToken(user, testSID)
	want := f.parseClaims(token)
	// One store call answers both the blacklist and the revocation instant.
	f.revocations.EXPECT().Check(gomock.Any(), want.ID, user.ID).Return(false, time.Time{}, nil)

	got, err := f.svc.ValidateAccessToken(t.Context(), token)

	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, testSID, got.SessionID)
	assert.Equal(t, []string{domain.RoleViewer}, got.Roles)
}

func TestAuthService_ValidateAccessToken_ToleratesClockSkew(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	priv, _ := testKeys(t)
	tests := []struct {
		name string
		at   time.Time
	}{
		{"issued a few seconds in the future by a replica running ahead", f.now.Add(clockSkewLeeway / 2)},
		{"expired a few seconds ago on a replica running behind", f.now.Add(-testAccessTTL - clockSkewLeeway/2)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims := validClaims(user, tc.at)
			f.revocations.EXPECT().Check(gomock.Any(), claims.ID, user.ID).Return(false, time.Time{}, nil)

			got, err := f.svc.ValidateAccessToken(t.Context(), craftToken(t, jwt.SigningMethodRS256, priv, claims))

			require.NoError(t, err)
			assert.Equal(t, claims.ID, got.ID)
		})
	}
}

func TestAuthService_ValidateAccessToken_RejectsUntrustedTokens(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t) // no store expectations: a rejected token never reaches the stores
	user := f.user()
	priv, pub := testKeys(t)
	foreignPriv, _ := foreignKeys(t)
	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	require.NoError(t, err)
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	withIssuer := validClaims(user, f.now)
	withIssuer.Issuer = "another-service"
	withoutJTI := validClaims(user, f.now)
	withoutJTI.ID = ""
	withoutIAT := validClaims(user, f.now)
	withoutIAT.IssuedAt = nil
	withoutEXP := validClaims(user, f.now)
	withoutEXP.ExpiresAt = nil

	tests := []struct {
		name  string
		token string
		want  string
	}{
		{"signed by another key", craftToken(t, jwt.SigningMethodRS256, foreignPriv, validClaims(user, f.now)), "invalid token"},
		{"HS256 signed with the public key", craftToken(t, jwt.SigningMethodHS256, pubPEM, validClaims(user, f.now)), "invalid token"},
		{"unsigned", craftToken(t, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, validClaims(user, f.now)), "invalid token"},
		{"expired", craftToken(t, jwt.SigningMethodRS256, priv, validClaims(user, f.now.Add(-time.Hour))), "token has expired"},
		{"issued by another service", craftToken(t, jwt.SigningMethodRS256, priv, withIssuer), "invalid token"},
		{"without jti", craftToken(t, jwt.SigningMethodRS256, priv, withoutJTI), "invalid token"},
		{"without iat", craftToken(t, jwt.SigningMethodRS256, priv, withoutIAT), "invalid token"},
		{"without exp", craftToken(t, jwt.SigningMethodRS256, priv, withoutEXP), "invalid token"},
		{"not a JWT", "not.a.jwt", "invalid token"},
		{"empty", "", "invalid token"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			claims, err := f.svc.ValidateAccessToken(t.Context(), tc.token)

			assert.Nil(t, claims)
			appErr := requireAppError(t, err, apperror.CodeUnauthorized)
			assert.Equal(t, tc.want, appErr.Message)
		})
	}
}

func TestAuthService_ValidateAccessToken_AppliesRevocationRules(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		setup   func(f *authFixture, claims *port.Claims)
		revoked bool
	}{
		{
			name: "blacklisted jti",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(true, time.Time{}, nil)
			},
			revoked: true,
		},
		{
			name: "blacklisted jti is rejected without consulting the sessions",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(true, claims.IssuedAt.Time, nil)
			},
			revoked: true,
		},
		{
			name: "issued before the revocation instant",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, claims.IssuedAt.Add(time.Second), nil)
			},
			revoked: true,
		},
		{
			name: "issued after the revocation instant",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, claims.IssuedAt.Add(-time.Second), nil)
			},
			revoked: false,
		},
		{
			name: "issued within the revocation second while its session is live",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, claims.IssuedAt.Time, nil)
				f.sessions.EXPECT().ListForUser(gomock.Any(), claims.UserID).Return([]domain.Session{{ID: "other"}, {ID: testSID}}, nil)
			},
			revoked: false,
		},
		{
			name: "issued within the revocation second after its session ended",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, claims.IssuedAt.Time, nil)
				f.sessions.EXPECT().ListForUser(gomock.Any(), claims.UserID).Return([]domain.Session{{ID: "other"}}, nil)
			},
			revoked: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			token := f.issuedToken(f.user(), testSID)
			want := f.parseClaims(token)
			tc.setup(f, want)

			got, err := f.svc.ValidateAccessToken(t.Context(), token)

			if tc.revoked {
				assert.Nil(t, got)
				appErr := requireAppError(t, err, apperror.CodeUnauthorized)
				assert.Equal(t, msgRevoked, appErr.Message)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestAuthService_ValidateAccessToken_FailsClosedWhenStoresAreDown(t *testing.T) {
	t.Parallel()
	boom := errors.New("redis down")
	tests := []struct {
		name  string
		setup func(f *authFixture, claims *port.Claims)
	}{
		{
			name: "revocation check",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, time.Time{}, boom)
			},
		},
		{
			name: "session lookup within the revocation second",
			setup: func(f *authFixture, claims *port.Claims) {
				f.revocations.EXPECT().Check(gomock.Any(), claims.ID, claims.UserID).Return(false, claims.IssuedAt.Time, nil)
				f.sessions.EXPECT().ListForUser(gomock.Any(), claims.UserID).Return(nil, boom)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t)
			token := f.issuedToken(f.user(), testSID)
			tc.setup(f, f.parseClaims(token))

			got, err := f.svc.ValidateAccessToken(t.Context(), token)

			assert.Nil(t, got)
			appErr := requireAppError(t, err, apperror.CodeServiceUnavailable)
			assert.Equal(t, http.StatusServiceUnavailable, appErr.HTTPStatus)
		})
	}
}

func TestAuthService_PublicJWKS_DescribesSigningKey(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	_, pub := testKeys(t)

	raw, err := f.svc.PublicJWKS()

	require.NoError(t, err)
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	require.NoError(t, json.Unmarshal(raw, &jwks))
	require.Len(t, jwks.Keys, 1)
	key := jwks.Keys[0]
	assert.Equal(t, "RSA", key["kty"])
	assert.Equal(t, "sig", key["use"])
	assert.Equal(t, jwt.SigningMethodRS256.Alg(), key["alg"])
	assert.True(t, isHex(key["kid"], kidLength))
	modulus, err := base64.RawURLEncoding.DecodeString(key["n"])
	require.NoError(t, err)
	assert.Equal(t, pub.N.Bytes(), modulus)
	exponent, err := base64.RawURLEncoding.DecodeString(key["e"])
	require.NoError(t, err)
	assert.Equal(t, int64(pub.E), new(big.Int).SetBytes(exponent).Int64())

	token := f.issuedToken(f.user(), testSID)
	parsed, _, err := jwt.NewParser().ParseUnverified(token, &port.Claims{})
	require.NoError(t, err)
	assert.Equal(t, key["kid"], parsed.Header["kid"], "issued tokens reference the published key")
}

func TestAuthService_PublicJWKS_ReturnsACopy(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)

	first, err := f.svc.PublicJWKS()
	require.NoError(t, err)
	first[0] = 'x'
	second, err := f.svc.PublicJWKS()
	require.NoError(t, err)

	assert.Equal(t, byte('{'), second[0])
	assert.NotEqual(t, first, second)
}
