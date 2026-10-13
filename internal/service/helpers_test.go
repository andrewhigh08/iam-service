package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/port"
	"github.com/andrewhigh08/iam-service/test/mocks"
)

// Fixture values shared by the service tests.
const (
	testUserID      int64 = 42
	testEmail             = "alice@example.com"
	testPassword          = "Correct-Horse-1!"
	testNewPassword       = "Battery-Staple-2?"
	testAccessTTL         = 15 * time.Minute
	testRefreshTTL        = 7 * 24 * time.Hour
	testMaxAttempts       = 3
	testLockout           = 10 * time.Minute
)

// RSA key generation dominates the run time of these tests, so each pair is generated once
// per process: signingKey is the pair the AuthService under test signs with and foreignKey a
// pair it must never trust.
var (
	signingKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, rsaKeyBits)
	})
	foreignKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, rsaKeyBits)
	})
	// shortKey is a pair below the minimum size the service accepts.
	shortKey = sync.OnceValues(func() (*rsa.PrivateKey, error) {
		return rsa.GenerateKey(rand.Reader, 1024)
	})
)

func testKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	key, err := signingKey()
	require.NoError(t, err)
	return key, &key.PublicKey
}

// shortKeys returns a 1024-bit key pair, which the service must refuse to sign with.
func shortKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	key, err := shortKey()
	require.NoError(t, err)
	return key, &key.PublicKey
}

func foreignKeys(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	t.Helper()
	key, err := foreignKey()
	require.NoError(t, err)
	return key, &key.PublicKey
}

// testPasswordHash returns a bcrypt hash of pw at the minimum cost; the services verify
// hashes of any cost, and the cheap cost keeps the fixtures fast.
func testPasswordHash(t *testing.T, pw string) string {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	require.NoError(t, err)
	return string(hash)
}

// newTestUser returns an active user whose password is testPassword and whose password was
// changed an hour before now.
func newTestUser(t *testing.T, now time.Time) *domain.User {
	t.Helper()
	return &domain.User{
		ID:                testUserID,
		Email:             testEmail,
		PasswordHash:      testPasswordHash(t, testPassword),
		PasswordChangedAt: now.Add(-time.Hour),
		FullName:          "Alice Example",
		CreatedAt:         now.Add(-24 * time.Hour),
		UpdatedAt:         now.Add(-time.Hour),
	}
}

func testAuthConfig(t *testing.T) AuthConfig {
	t.Helper()
	priv, pub := testKeys(t)
	return AuthConfig{
		PrivateKey:       priv,
		PublicKey:        pub,
		AccessTTL:        testAccessTTL,
		RefreshTTL:       testRefreshTTL,
		MaxLoginAttempts: testMaxAttempts,
		LockoutDuration:  testLockout,
	}
}

// authFixture is an AuthService wired to gomock stores with a frozen clock.
type authFixture struct {
	t           *testing.T
	svc         *AuthService
	users       *mocks.MockUserRepository
	authz       *mocks.MockAuthorizationService
	audit       *mocks.MockAuditService
	sessions    *mocks.MockSessionStore
	revocations *mocks.MockRevocationStore
	attempts    *mocks.MockLoginAttemptStore
	now         time.Time
	meta        domain.ClientMeta
}

// newAuthFixture builds an AuthService on fresh mocks. The clock is frozen at the current
// second so that issued tokens validate against the real clock while every timestamp the
// service produces is predictable. opts adjust the configuration before construction.
func newAuthFixture(t *testing.T, opts ...func(*AuthConfig)) *authFixture {
	t.Helper()
	ctrl := gomock.NewController(t)
	f := &authFixture{
		t:           t,
		users:       mocks.NewMockUserRepository(ctrl),
		authz:       mocks.NewMockAuthorizationService(ctrl),
		audit:       mocks.NewMockAuditService(ctrl),
		sessions:    mocks.NewMockSessionStore(ctrl),
		revocations: mocks.NewMockRevocationStore(ctrl),
		attempts:    mocks.NewMockLoginAttemptStore(ctrl),
		now:         time.Now().Truncate(time.Second),
		meta:        domain.ClientMeta{IP: "203.0.113.7", UserAgent: "test-agent/1.0"},
	}
	cfg := testAuthConfig(t)
	for _, opt := range opts {
		opt(&cfg)
	}
	svc, err := NewAuthService(f.deps(), cfg)
	require.NoError(t, err)
	svc.now = func() time.Time { return f.now }
	f.svc = svc
	return f
}

func (f *authFixture) deps() AuthDeps {
	return AuthDeps{
		Users:       f.users,
		Authz:       f.authz,
		Audit:       f.audit,
		Sessions:    f.sessions,
		Revocations: f.revocations,
		Attempts:    f.attempts,
	}
}

func (f *authFixture) user() *domain.User {
	return newTestUser(f.t, f.now)
}

func (f *authFixture) expectCredentialsOK(user *domain.User) {
	f.attempts.EXPECT().IsLocked(gomock.Any(), user.Email).Return(false, nil)
	f.users.EXPECT().FindByEmail(gomock.Any(), user.Email).Return(user, nil)
	f.attempts.EXPECT().Reset(gomock.Any(), user.Email).Return(nil)
}

func (f *authFixture) expectIssue(user *domain.User, roles []string) *domain.Session {
	f.authz.EXPECT().RolesOf(gomock.Any(), user.ID).Return(roles, nil)
	stored, _ := f.expectSessionCreate()
	return stored
}

// expectSessionCreate expects one session creation with the refresh TTL and returns the
// stored session together with the expectation, for ordering.
func (f *authFixture) expectSessionCreate() (*domain.Session, *gomock.Call) {
	stored := &domain.Session{}
	call := f.sessions.EXPECT().Create(gomock.Any(), gomock.Any(), testRefreshTTL).
		DoAndReturn(func(_ context.Context, s domain.Session, _ time.Duration) error {
			*stored = s
			return nil
		})
	return stored, call
}

func (f *authFixture) issuedToken(user *domain.User, sid string) string {
	f.t.Helper()
	token, _, err := f.svc.signAccessToken(user, []string{domain.RoleViewer}, sid, f.now)
	require.NoError(f.t, err)
	return token
}

func (f *authFixture) parseClaims(token string) *port.Claims {
	f.t.Helper()
	claims := &port.Claims{}
	parsed, err := jwt.ParseWithClaims(token, claims,
		func(*jwt.Token) (any, error) { return f.svc.cfg.PublicKey, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}))
	require.NoError(f.t, err)
	require.True(f.t, parsed.Valid)
	return claims
}

func auditAction(action string) gomock.Matcher {
	return gomock.Cond(func(e domain.AuditEvent) bool { return e.Action == action })
}

func expectAudit(audit *mocks.MockAuditService, action string) *domain.AuditEvent {
	recorded := &domain.AuditEvent{}
	audit.EXPECT().Record(gomock.Any(), auditAction(action)).
		DoAndReturn(func(_ context.Context, e domain.AuditEvent) error {
			*recorded = e
			return nil
		})
	return recorded
}

func requireAppError(t *testing.T, err error, code string) *apperror.AppError {
	t.Helper()
	var appErr *apperror.AppError
	require.ErrorAs(t, err, &appErr)
	require.Equal(t, code, appErr.Code)
	return appErr
}

func isHex(s string, n int) bool {
	_, err := hex.DecodeString(s)
	return err == nil && len(s) == n && strings.ToLower(s) == s
}

func TestHashPassword_UsesTheDefaultCost(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword(testPassword)

	require.NoError(t, err)
	require.NoError(t, bcrypt.CompareHashAndPassword([]byte(hash), []byte(testPassword)))
	cost, err := bcrypt.Cost([]byte(hash))
	require.NoError(t, err)
	assert.Equal(t, bcrypt.DefaultCost, cost)
}

func TestHashPassword_ReportsBcryptFailures(t *testing.T) {
	t.Parallel()

	hash, err := hashPassword(strings.Repeat("x", 73)) // bcrypt hashes at most 72 bytes

	assert.Empty(t, hash)
	appErr := requireAppError(t, err, apperror.CodeInternal)
	assert.Equal(t, msgHashingFailed, appErr.Message)
	require.ErrorIs(t, err, bcrypt.ErrPasswordTooLong)
}

func TestBoundResourceID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"short id is untouched", testEmail, testEmail},
		{"id at the limit is untouched", strings.Repeat("a", maxResourceIDBytes), strings.Repeat("a", maxResourceIDBytes)},
		{"longer id is cut at the limit", strings.Repeat("a", maxResourceIDBytes+1), strings.Repeat("a", maxResourceIDBytes)},
		{"a character is never split", strings.Repeat("a", maxResourceIDBytes-1) + "éé", strings.Repeat("a", maxResourceIDBytes-1)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, boundResourceID(tt.in))
		})
	}
}
