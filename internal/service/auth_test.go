package service

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
	"github.com/andrewhigh08/iam-service/internal/port"
)

func TestNewAuthService_RejectsMissingDependencies(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		strip func(*AuthDeps)
		want  string
	}{
		{"user repository", func(d *AuthDeps) { d.Users = nil }, "user repository is required"},
		{"authorization service", func(d *AuthDeps) { d.Authz = nil }, "authorization service is required"},
		{"audit service", func(d *AuthDeps) { d.Audit = nil }, "audit service is required"},
		{"session store", func(d *AuthDeps) { d.Sessions = nil }, "session store is required"},
		{"revocation store", func(d *AuthDeps) { d.Revocations = nil }, "revocation store is required"},
		{"login attempt store", func(d *AuthDeps) { d.Attempts = nil }, "login attempt store is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deps := newAuthFixture(t).deps()
			tc.strip(&deps)
			svc, err := NewAuthService(deps, testAuthConfig(t))
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, svc)
		})
	}
}

func TestNewAuthService_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()
	_, foreignPub := foreignKeys(t)
	shortPriv, shortPub := shortKeys(t)
	tests := []struct {
		name   string
		mutate func(*AuthConfig)
		want   string
	}{
		{"missing private key", func(c *AuthConfig) { c.PrivateKey = nil }, "RSA key pair is required"},
		{"missing public key", func(c *AuthConfig) { c.PublicKey = nil }, "RSA key pair is required"},
		{"key shorter than 2048 bits", func(c *AuthConfig) { c.PrivateKey, c.PublicKey = shortPriv, shortPub }, "at least 2048 bits"},
		{"public key of another pair", func(c *AuthConfig) { c.PublicKey = foreignPub }, "does not match"},
		{"zero access TTL", func(c *AuthConfig) { c.AccessTTL = 0 }, "TTLs must be positive"},
		{"negative refresh TTL", func(c *AuthConfig) { c.RefreshTTL = -time.Second }, "TTLs must be positive"},
		{"negative session max age", func(c *AuthConfig) { c.SessionMaxAge = -time.Hour }, "session max age"},
		{"no login attempts allowed", func(c *AuthConfig) { c.MaxLoginAttempts = 0 }, "max login attempts"},
		{"zero lockout", func(c *AuthConfig) { c.LockoutDuration = 0 }, "lockout duration"},
		{"negative password max age", func(c *AuthConfig) { c.PasswordMaxAge = -time.Hour }, "password max age"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := testAuthConfig(t)
			tc.mutate(&cfg)
			svc, err := NewAuthService(newAuthFixture(t).deps(), cfg)
			require.ErrorContains(t, err, tc.want)
			assert.Nil(t, svc)
		})
	}
}

func TestNewAuthService_AppliesDefaults(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)

	svc, err := NewAuthService(f.deps(), testAuthConfig(t))

	require.NoError(t, err)
	assert.Equal(t, defaultIssuer, svc.cfg.Issuer)
	assert.Equal(t, validator.DefaultPolicy(), svc.cfg.PasswordPolicy)
	assert.True(t, isHex(svc.kid, kidLength))
}

func TestAuthService_Login_IssuesTokenPair(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	f.expectCredentialsOK(user)
	stored := f.expectIssue(user, []string{domain.RoleViewer})
	event := expectAudit(f.audit, domain.AuditActionLoginSuccess)

	res, err := f.svc.Login(t.Context(), "  Alice@Example.COM ", testPassword, f.meta)

	require.NoError(t, err)
	require.NotNil(t, res.Tokens)
	assert.False(t, res.RequirePasswordChange)
	assert.Empty(t, res.Reason)
	assert.Equal(t, int64(testAccessTTL/time.Second), res.Tokens.ExpiresIn)
	assert.Same(t, user, res.User, "the result identifies the user without decoding the token")
	assert.Equal(t, []string{domain.RoleViewer}, res.Roles)

	assert.True(t, isHex(res.Tokens.RefreshToken, 2*refreshTokenBytes), "refresh token is random hex")
	assert.Equal(t, hashToken(res.Tokens.RefreshToken), stored.TokenHash, "session is keyed by the token digest")
	assert.Equal(t, sessionID(stored.TokenHash), stored.ID)
	assert.Equal(t, user.ID, stored.UserID)
	assert.Equal(t, f.now, stored.CreatedAt)
	assert.Equal(t, f.now.Add(testRefreshTTL), stored.ExpiresAt)
	assert.Equal(t, f.meta.IP, stored.IP)
	assert.Equal(t, f.meta.UserAgent, stored.UserAgent)

	claims := f.parseClaims(res.Tokens.AccessToken)
	assert.Equal(t, user.ID, claims.UserID)
	assert.Equal(t, user.Email, claims.Email)
	assert.Equal(t, []string{domain.RoleViewer}, claims.Roles)
	assert.Equal(t, stored.ID, claims.SessionID)
	assert.True(t, isHex(claims.ID, 2*jtiBytes), "jti is random hex")
	assert.Equal(t, claims.ID, stored.AccessJTI, "the session records the access token it was issued with")
	assert.Equal(t, f.now.Add(testAccessTTL), stored.AccessExpiresAt)
	assert.Equal(t, defaultIssuer, claims.Issuer)
	assert.Equal(t, "42", claims.Subject)
	assert.Equal(t, f.now.Unix(), claims.IssuedAt.Unix())
	assert.Equal(t, f.now.Add(testAccessTTL).Unix(), claims.ExpiresAt.Unix())

	assert.Equal(t, user.ID, event.ActorID)
	assert.Equal(t, domain.AuditResourceTypeUser, event.ResourceType)
	assert.Equal(t, "42", event.ResourceID)
	assert.Equal(t, map[string]any{"sid": stored.ID}, event.Details)
	assert.Equal(t, f.meta, event.ClientMeta)
}

func TestAuthService_Login_EncodesMissingRolesAsEmptyList(t *testing.T) {
	t.Parallel()
	f := newAuthFixture(t)
	user := f.user()
	f.expectCredentialsOK(user)
	f.expectIssue(user, nil)
	expectAudit(f.audit, domain.AuditActionLoginSuccess)

	res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

	require.NoError(t, err)
	parts := strings.Split(res.Tokens.AccessToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	assert.Contains(t, string(payload), `"roles":[]`)
	claims := f.parseClaims(res.Tokens.AccessToken)
	assert.NotNil(t, claims.Roles)
	assert.Empty(t, claims.Roles)
	assert.NotNil(t, res.Roles)
	assert.Empty(t, res.Roles)
}

func TestAuthService_Login_CapsSessionAtMaxAge(t *testing.T) {
	t.Parallel()
	const maxAge = time.Hour
	f := newAuthFixture(t, func(c *AuthConfig) { c.SessionMaxAge = maxAge })
	user := f.user()
	f.expectCredentialsOK(user)
	f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return(nil, nil)
	stored := &domain.Session{}
	f.sessions.EXPECT().Create(gomock.Any(), gomock.Any(), maxAge).DoAndReturn(func(_ context.Context, s domain.Session, _ time.Duration) error {
		*stored = s
		return nil
	})
	expectAudit(f.audit, domain.AuditActionLoginSuccess)

	_, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

	require.NoError(t, err)
	assert.Equal(t, f.now.Add(maxAge), stored.ExpiresAt, "a maximum age below the refresh TTL bounds the session")
}

func TestAuthService_Login_RequiresPasswordChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		maxAge  time.Duration
		prepare func(u *domain.User, now time.Time)
		reason  string
	}{
		{
			name:    "temporary password",
			prepare: func(u *domain.User, _ time.Time) { u.PasswordTemporary = true },
			reason:  port.ReasonTemporaryPassword,
		},
		{
			name:    "expired password",
			maxAge:  24 * time.Hour,
			prepare: func(u *domain.User, now time.Time) { u.PasswordChangedAt = now.Add(-48 * time.Hour) },
			reason:  port.ReasonPasswordExpired,
		},
		{
			name:   "temporary password takes precedence over expiry",
			maxAge: 24 * time.Hour,
			prepare: func(u *domain.User, now time.Time) {
				u.PasswordTemporary = true
				u.PasswordChangedAt = now.Add(-48 * time.Hour)
			},
			reason: port.ReasonTemporaryPassword,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t, func(c *AuthConfig) { c.PasswordMaxAge = tc.maxAge })
			user := f.user()
			tc.prepare(user, f.now)
			f.expectCredentialsOK(user)
			event := expectAudit(f.audit, domain.AuditActionLoginSuccess)

			res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

			require.NoError(t, err)
			assert.Nil(t, res.Tokens, "no tokens before the password is changed")
			assert.True(t, res.RequirePasswordChange)
			assert.Equal(t, tc.reason, res.Reason)
			assert.Equal(t, map[string]any{"require_password_change": true, "reason": tc.reason}, event.Details)
		})
	}
}

func TestAuthService_Login_PasswordExpiryBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		maxAge time.Duration
		age    time.Duration
	}{
		{"max age zero disables expiry", 0, 10 * 365 * 24 * time.Hour},
		{"password exactly at max age is still valid", 24 * time.Hour, 24 * time.Hour},
		{"recent password", 24 * time.Hour, time.Hour},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newAuthFixture(t, func(c *AuthConfig) { c.PasswordMaxAge = tc.maxAge })
			user := f.user()
			user.PasswordChangedAt = f.now.Add(-tc.age)
			f.expectCredentialsOK(user)
			f.expectIssue(user, []string{domain.RoleAnalyst})
			expectAudit(f.audit, domain.AuditActionLoginSuccess)

			res, err := f.svc.Login(t.Context(), testEmail, testPassword, f.meta)

			require.NoError(t, err)
			assert.False(t, res.RequirePasswordChange)
			assert.NotNil(t, res.Tokens)
		})
	}
}
