package service

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// Sizes of the random identifiers issued by the service.
const (
	refreshTokenBytes = 32 // random bytes in a refresh token (64 hex characters)
	jtiBytes          = 16 // random bytes in a jti claim
	kidLength         = 16 // hex characters of the key digest that form the kid
)

// issuedTokens is the outcome of issueTokens: the pair, the sid of the new session and the
// roles encoded in the access token.
type issuedTokens struct {
	tokens *port.TokenPair
	sid    string
	roles  []string
}

// issueTokens loads the user's roles, signs an access token and opens the refresh-token
// session. createdAt is the session start, preserved across rotations; the zero value means
// now. The session records the access token's jti so that revoking it can blacklist the token.
func (s *AuthService) issueTokens(ctx context.Context, user *domain.User, meta domain.ClientMeta, createdAt time.Time) (*issuedTokens, error) {
	roles, err := s.deps.Authz.RolesOf(ctx, user.ID)
	if err != nil {
		return nil, asInternal("failed to load user roles", err)
	}
	if roles == nil {
		roles = []string{}
	}
	refreshToken, err := randomHex(refreshTokenBytes)
	if err != nil {
		return nil, apperror.Internal("failed to generate refresh token", err)
	}
	tokenHash := hashToken(refreshToken)
	sid := sessionID(tokenHash)
	now := s.now()
	if createdAt.IsZero() {
		createdAt = now
	}
	ttl := s.sessionTTL(createdAt, now)
	if ttl <= 0 {
		return nil, apperror.Internal("session has exceeded its maximum age", nil)
	}
	accessToken, jti, err := s.signAccessToken(user, roles, sid, now)
	if err != nil {
		return nil, apperror.Internal("failed to sign access token", err)
	}
	session := domain.Session{
		ID:              sid,
		TokenHash:       tokenHash,
		UserID:          user.ID,
		CreatedAt:       createdAt,
		ExpiresAt:       now.Add(ttl),
		IP:              meta.IP,
		UserAgent:       meta.UserAgent,
		AccessJTI:       jti,
		AccessExpiresAt: now.Add(s.cfg.AccessTTL),
	}
	if err := s.deps.Sessions.Create(ctx, session, ttl); err != nil {
		return nil, asInternal("failed to create session", err)
	}
	return &issuedTokens{
		tokens: &port.TokenPair{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
			ExpiresIn:    int64(s.cfg.AccessTTL / time.Second),
		},
		sid:   sid,
		roles: roles,
	}, nil
}

// sessionTTL returns how long a session started at createdAt may live from now: the refresh
// TTL, capped so that the session never outlives its maximum age when one is configured.
func (s *AuthService) sessionTTL(createdAt, now time.Time) time.Duration {
	ttl := s.cfg.RefreshTTL
	if s.cfg.SessionMaxAge > 0 {
		ttl = min(ttl, createdAt.Add(s.cfg.SessionMaxAge).Sub(now))
	}
	return ttl
}

func (s *AuthService) signAccessToken(user *domain.User, roles []string, sid string, now time.Time) (token, jti string, err error) {
	jti, err = randomHex(jtiBytes)
	if err != nil {
		return "", "", err
	}
	if roles == nil {
		roles = []string{}
	}
	claims := port.Claims{
		UserID:    user.ID,
		Email:     user.Email,
		Roles:     roles,
		SessionID: sid,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			Issuer:    s.cfg.Issuer,
			Subject:   formatID(user.ID),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTTL)),
		},
	}
	signed := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed.Header["kid"] = s.kid
	token, err = signed.SignedString(s.cfg.PrivateKey)
	if err != nil {
		return "", "", err
	}
	return token, jti, nil
}

// ValidateAccessToken verifies token and the revocation state of its jti and user. A failing
// revocation or session store yields apperror.ServiceUnavailable: validation fails closed.
func (s *AuthService) ValidateAccessToken(ctx context.Context, token string) (*port.Claims, error) {
	claims, err := s.parseAccessToken(token)
	if err != nil {
		return nil, err
	}
	revoked, revokedBefore, err := s.deps.Revocations.Check(ctx, claims.ID, claims.UserID)
	if err != nil {
		return nil, s.revocationUnavailable(ctx, err)
	}
	if !revoked {
		revoked, err = s.revokedByUser(ctx, claims, revokedBefore)
		if err != nil {
			return nil, s.revocationUnavailable(ctx, err)
		}
	}
	if revoked {
		return nil, apperror.Unauthorized(msgRevoked)
	}
	return claims, nil
}

// revokedByUser reports whether the user-wide revocation instant covers the token. Both the
// instant and iat have second resolution, so a token issued within the revocation second is
// ambiguous: it is accepted only while its session is live. The instant is recorded before
// the sessions are deleted, so every session that existed at the instant is gone, and a
// session that is still live was opened after it.
func (s *AuthService) revokedByUser(ctx context.Context, claims *port.Claims, revokedBefore time.Time) (bool, error) {
	if revokedBefore.IsZero() {
		return false, nil
	}
	iat := claims.IssuedAt.Truncate(time.Second)
	switch {
	case iat.Before(revokedBefore):
		return true, nil
	case iat.After(revokedBefore):
		return false, nil
	}
	sessions, err := s.deps.Sessions.ListForUser(ctx, claims.UserID)
	if err != nil {
		return false, err
	}
	live := slices.ContainsFunc(sessions, func(sess domain.Session) bool { return sess.ID == claims.SessionID })
	return !live, nil
}

func (s *AuthService) revocationUnavailable(ctx context.Context, err error) error {
	s.logger.FromContext(ctx).Error("revocation store unavailable", "error", err)
	return apperror.ServiceUnavailable("token validation is temporarily unavailable")
}

// parseAccessToken checks the signature, algorithm, issuer, expiry and issue time of token
// and requires the jti claim.
func (s *AuthService) parseAccessToken(token string) (*port.Claims, error) {
	claims := &port.Claims{}
	parsed, err := s.parser.ParseWithClaims(token, claims, func(*jwt.Token) (any, error) {
		return s.cfg.PublicKey, nil
	})
	if errors.Is(err, jwt.ErrTokenExpired) {
		return nil, apperror.Unauthorized("token has expired")
	}
	if err != nil || !parsed.Valid || claims.ID == "" || claims.IssuedAt == nil {
		return nil, apperror.Unauthorized("invalid token")
	}
	return claims, nil
}

// PublicJWKS returns the JSON Web Key Set holding the public signing key.
func (s *AuthService) PublicJWKS() ([]byte, error) {
	return bytes.Clone(s.jwks), nil
}

// jsonWebKey is the RFC 7517 representation of an RSA public signing key.
type jsonWebKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jsonWebKeySet struct {
	Keys []jsonWebKey `json:"keys"`
}

// buildJWKS renders pub as a JWKS document and returns the kid with it. The kid is the first
// 16 hex digits of the SHA-256 digest of the DER-encoded key, so it changes with the key.
func buildJWKS(pub *rsa.PublicKey) (kid string, jwks []byte, err error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", nil, fmt.Errorf("auth service: encode public key: %w", err)
	}
	digest := sha256.Sum256(der)
	kid = hex.EncodeToString(digest[:])[:kidLength]
	key := jsonWebKey{
		Kty: "RSA",
		Use: "sig",
		Alg: jwt.SigningMethodRS256.Alg(),
		Kid: kid,
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
	jwks, err = json.Marshal(jsonWebKeySet{Keys: []jsonWebKey{key}})
	if err != nil {
		return "", nil, fmt.Errorf("auth service: encode JWKS: %w", err)
	}
	return kid, jwks, nil
}

func randomHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

// hashToken returns the hex SHA-256 digest under which a refresh token's session is stored.
func hashToken(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func sessionID(tokenHash string) string {
	return tokenHash[:domain.SessionIDLength]
}
