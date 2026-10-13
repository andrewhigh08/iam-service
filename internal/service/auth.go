package service

import (
	"context"
	"crypto/rsa"
	"errors"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/metrics"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
	"github.com/andrewhigh08/iam-service/internal/port"
)

const (
	// defaultIssuer is the iss claim used when AuthConfig.Issuer is empty.
	defaultIssuer = "iam-service"
	// clockSkewLeeway is the clock difference tolerated between the replica that issued a token
	// and the one validating it, so a token minted a moment ago is not rejected as "not yet valid".
	clockSkewLeeway = 30 * time.Second
)

// AuthDeps lists the collaborators of AuthService. Logger may be nil.
type AuthDeps struct {
	Users       port.UserRepository
	Authz       port.AuthorizationService
	Audit       port.AuditService
	Sessions    port.SessionStore
	Revocations port.RevocationStore
	Attempts    port.LoginAttemptStore
	Logger      *logger.Logger
}

// AuthConfig holds the signing keys and policy parameters of AuthService. An empty Issuer
// means "iam-service", a zero PasswordPolicy means validator.DefaultPolicy, a zero
// PasswordMaxAge disables password expiry and a zero SessionMaxAge lets a session live as
// long as it keeps being refreshed.
type AuthConfig struct {
	PrivateKey       *rsa.PrivateKey
	PublicKey        *rsa.PublicKey
	Issuer           string
	AccessTTL        time.Duration
	RefreshTTL       time.Duration
	SessionMaxAge    time.Duration
	MaxLoginAttempts int
	LockoutDuration  time.Duration
	PasswordMaxAge   time.Duration
	PasswordPolicy   validator.Policy
}

// AuthService implements port.AuthService with RS256 access tokens and refresh-token sessions.
type AuthService struct {
	deps    AuthDeps
	cfg     AuthConfig
	revoker accessRevoker
	parser  *jwt.Parser
	kid     string
	jwks    []byte
	logger  *logger.Logger
	now     func() time.Time
}

// NewAuthService validates deps and cfg and prepares the token parser and the JWKS document.
func NewAuthService(deps AuthDeps, cfg AuthConfig) (*AuthService, error) {
	if err := validateAuthDeps(deps); err != nil {
		return nil, err
	}
	if err := validateAuthConfig(&cfg); err != nil {
		return nil, err
	}
	kid, jwks, err := buildJWKS(cfg.PublicKey)
	if err != nil {
		return nil, err
	}
	return &AuthService{
		deps: deps,
		cfg:  cfg,
		revoker: accessRevoker{
			sessions:    deps.Sessions,
			revocations: deps.Revocations,
			accessTTL:   cfg.AccessTTL,
		},
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{jwt.SigningMethodRS256.Alg()}),
			jwt.WithIssuer(cfg.Issuer),
			jwt.WithExpirationRequired(),
			jwt.WithIssuedAt(),
			jwt.WithLeeway(clockSkewLeeway),
		),
		kid:    kid,
		jwks:   jwks,
		logger: componentLogger(deps.Logger, "auth"),
		now:    time.Now,
	}, nil
}

// validateAuthDeps rejects missing collaborators.
func validateAuthDeps(deps AuthDeps) error {
	var missing string
	switch {
	case deps.Users == nil:
		missing = "user repository"
	case deps.Authz == nil:
		missing = "authorization service"
	case deps.Audit == nil:
		missing = "audit service"
	case deps.Sessions == nil:
		missing = "session store"
	case deps.Revocations == nil:
		missing = "revocation store"
	case deps.Attempts == nil:
		missing = "login attempt store"
	default:
		return nil
	}
	return errors.New("auth service: " + missing + " is required")
}

// validateAuthConfig checks the keys and limits of cfg and fills in the defaults.
func validateAuthConfig(cfg *AuthConfig) error {
	switch {
	case cfg.PrivateKey == nil || cfg.PublicKey == nil:
		return errors.New("auth service: RSA key pair is required")
	case cfg.PrivateKey.N.BitLen() < minRSAKeyBits:
		return errors.New("auth service: RSA key must have at least 2048 bits")
	case !cfg.PrivateKey.PublicKey.Equal(cfg.PublicKey):
		return errors.New("auth service: public key does not match private key")
	case cfg.AccessTTL <= 0 || cfg.RefreshTTL <= 0:
		return errors.New("auth service: token TTLs must be positive")
	case cfg.SessionMaxAge < 0:
		return errors.New("auth service: session max age must not be negative")
	case cfg.MaxLoginAttempts < 1:
		return errors.New("auth service: max login attempts must be at least 1")
	case cfg.LockoutDuration <= 0:
		return errors.New("auth service: lockout duration must be positive")
	case cfg.PasswordMaxAge < 0:
		return errors.New("auth service: password max age must not be negative")
	}
	if cfg.Issuer == "" {
		cfg.Issuer = defaultIssuer
	}
	if cfg.PasswordPolicy == (validator.Policy{}) {
		cfg.PasswordPolicy = validator.DefaultPolicy()
	}
	return nil
}

// Login verifies the credentials and issues a token pair, or reports that the password must
// be changed first.
func (s *AuthService) Login(ctx context.Context, email, password string, meta domain.ClientMeta) (*port.LoginResult, error) {
	user, err := s.authenticate(ctx, normalizeEmail(email), password, meta)
	if err != nil {
		return nil, err
	}
	if reason := s.passwordChangeReason(user); reason != "" {
		s.audit(ctx, user.ID, domain.AuditActionLoginSuccess, formatID(user.ID), meta, map[string]any{
			"require_password_change": true,
			"reason":                  reason,
		})
		return &port.LoginResult{RequirePasswordChange: true, Reason: reason}, nil
	}
	issued, err := s.issueTokens(ctx, user, meta, time.Time{})
	if err != nil {
		return nil, err
	}
	s.audit(ctx, user.ID, domain.AuditActionLoginSuccess, formatID(user.ID), meta, map[string]any{"sid": issued.sid})
	s.logger.FromContext(ctx).Info("login succeeded", "user_id", user.ID, "sid", issued.sid)
	return &port.LoginResult{Tokens: issued.tokens, User: user, Roles: issued.roles}, nil
}

// passwordChangeReason returns why the user must change the password before receiving
// tokens, or "" when no change is required.
func (s *AuthService) passwordChangeReason(user *domain.User) string {
	switch {
	case user.PasswordTemporary:
		return port.ReasonTemporaryPassword
	case user.PasswordExpired(s.now(), s.cfg.PasswordMaxAge):
		return port.ReasonPasswordExpired
	default:
		return ""
	}
}

// authenticate verifies the password of the account identified by the normalized email while
// enforcing the lockout policy. Rejections are counted and audited, and their messages do not
// reveal whether the account exists.
func (s *AuthService) authenticate(ctx context.Context, email, password string, meta domain.ClientMeta) (*domain.User, error) {
	if err := s.checkLock(ctx, email, 0, meta); err != nil {
		return nil, err
	}
	user, err := s.deps.Users.FindByEmail(ctx, email)
	if isNotFound(err) {
		// Spend the same bcrypt work as for a known account before rejecting.
		_ = bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte(password))
		if rejectErr := s.rejectCredentials(ctx, email, 0, "user_not_found", meta); rejectErr != nil {
			return nil, rejectErr
		}
		return nil, apperror.Unauthorized(msgLoginRejected)
	}
	if err != nil {
		return nil, asInternal(msgLoadUserFailed, err)
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)) != nil {
		if rejectErr := s.rejectCredentials(ctx, email, user.ID, "invalid_password", meta); rejectErr != nil {
			return nil, rejectErr
		}
		return nil, apperror.Unauthorized(msgLoginRejected)
	}
	if user.IsBlocked {
		metrics.RecordAuthAttempt(metrics.ResultFailure)
		s.audit(ctx, user.ID, domain.AuditActionLoginFailed, formatID(user.ID), meta, map[string]any{"reason": "user_blocked"})
		return nil, apperror.Unauthorized(msgAccountBlocked)
	}
	s.resetAttempts(ctx, email)
	metrics.RecordAuthAttempt(metrics.ResultSuccess)
	return user, nil
}

// checkLock rejects a locked account before any credential is examined. The lock state must
// be known: when the attempt store cannot answer, the check fails closed with 503 rather than
// letting guesses through uncounted. userID identifies the account in the audit entry when
// the caller already knows it.
func (s *AuthService) checkLock(ctx context.Context, email string, userID int64, meta domain.ClientMeta) error {
	locked, err := s.deps.Attempts.IsLocked(ctx, email)
	if err != nil {
		metrics.RecordAuthAttempt(metrics.ResultFailure)
		return s.attemptsUnavailable(ctx, "failed to check login lock", err)
	}
	if !locked {
		return nil
	}
	metrics.RecordAuthAttempt(metrics.ResultLocked)
	s.audit(ctx, userID, domain.AuditActionLoginLocked, auditResourceID(email, userID), meta, map[string]any{
		"reason": "too_many_failed_attempts",
	})
	return apperror.Unauthorized(msgAccountLocked)
}

// rejectCredentials counts a failed attempt for email, locks the account once the limit is
// reached and audits the failure. It returns nil when the caller should answer with its own
// 401, or the fail-closed error when the attempt store could not record the failure.
func (s *AuthService) rejectCredentials(ctx context.Context, email string, userID int64, reason string, meta domain.ClientMeta) error {
	metrics.RecordAuthAttempt(metrics.ResultFailure)
	details := map[string]any{"reason": reason}
	resourceID := auditResourceID(email, userID)
	count, err := s.deps.Attempts.RecordFailure(ctx, email, s.cfg.LockoutDuration)
	if err != nil {
		s.audit(ctx, userID, domain.AuditActionLoginFailed, resourceID, meta, details)
		return s.attemptsUnavailable(ctx, "failed to record login failure", err)
	}
	details["attempts"] = count
	locked, err := s.lockWhenExceeded(ctx, email, count)
	if err != nil {
		s.audit(ctx, userID, domain.AuditActionLoginFailed, resourceID, meta, details)
		return s.attemptsUnavailable(ctx, "failed to lock account", err)
	}
	details["locked"] = locked
	s.audit(ctx, userID, domain.AuditActionLoginFailed, resourceID, meta, details)
	return nil
}

// lockWhenExceeded locks email once count reaches the configured limit and reports whether
// the account is now locked.
func (s *AuthService) lockWhenExceeded(ctx context.Context, email string, count int64) (bool, error) {
	if count < int64(s.cfg.MaxLoginAttempts) {
		return false, nil
	}
	if err := s.deps.Attempts.Lock(ctx, email, s.cfg.LockoutDuration); err != nil {
		return false, err
	}
	s.logger.FromContext(ctx).Warn("account locked after repeated login failures", "attempts", count)
	return true, nil
}

// resetAttempts clears the failure counter after a successful credential check; a failure to
// do so only shortens the window before a lockout and is logged.
func (s *AuthService) resetAttempts(ctx context.Context, email string) {
	if err := s.deps.Attempts.Reset(ctx, email); err != nil {
		s.logger.FromContext(ctx).Warn("failed to reset login attempts", "error", err)
	}
}

// attemptsUnavailable logs a login-attempt store failure and returns the error that refuses
// the credential check until the store is back.
func (s *AuthService) attemptsUnavailable(ctx context.Context, msg string, err error) error {
	s.logger.FromContext(ctx).Error(msg, "error", err)
	return apperror.ServiceUnavailable(msgLoginUnavailable)
}

// auditResourceID names the account of an audit entry: its id when known, else the address.
func auditResourceID(email string, userID int64) string {
	if userID != 0 {
		return formatID(userID)
	}
	return email
}

// audit records a security event; a failing audit store is logged, never surfaced.
func (s *AuthService) audit(ctx context.Context, actorID int64, action, resourceID string, meta domain.ClientMeta, details map[string]any) {
	err := s.deps.Audit.Record(ctx, domain.AuditEvent{
		ActorID:      actorID,
		Action:       action,
		ResourceType: domain.AuditResourceTypeUser,
		ResourceID:   resourceID,
		Details:      details,
		ClientMeta:   meta,
	})
	if err != nil {
		s.logger.FromContext(ctx).Error(msgRecordAuditFailed, "action", action, "error", err)
	}
}

var (
	dummyHashOnce sync.Once
	dummyHash     []byte
)

// dummyPasswordHash returns a bcrypt hash computed once at the cost used for real passwords.
// Comparing an unknown account's password against it keeps the response time of unknown and
// known accounts alike.
func dummyPasswordHash() []byte {
	dummyHashOnce.Do(func() {
		hash, err := bcrypt.GenerateFromPassword([]byte("iam-service dummy password"), bcrypt.DefaultCost)
		if err == nil {
			dummyHash = hash
		}
	})
	return dummyHash
}
