// Package service contains the business logic layer of the application.
//
// Services implement the business rules and orchestrate operations
// between repositories and other components.
package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// AuthService implements port.AuthService interface.
//
// Provides authentication operations including login, token validation,
// and password management using JWT RS256 signing.
type AuthService struct {
	userRepo         port.UserRepository       // User repository
	authz            port.AuthorizationService // Authorization service for roles
	auditService     port.AuditService         // Audit service for logging
	refreshCache     port.RefreshTokenCache    // Refresh token cache
	tokenCache       port.TokenCache           // Token blacklist cache
	rateLimitCache   port.RateLimitCache       // Rate limit cache for login attempts
	privateKey       *rsa.PrivateKey           // RSA private key for signing
	publicKey        *rsa.PublicKey            // RSA public key for verification
	tokenTTL         time.Duration             // Access token time-to-live
	refreshTTL       time.Duration             // Refresh token time-to-live
	maxLoginAttempts int                       // Max failed login attempts before lockout
	lockoutDuration  time.Duration             // Duration of account lockout
	passwordMaxAge   time.Duration             // Max password age (0 = no expiration)
	logger           *logger.Logger            // Logger instance
}

// AuthServiceConfig holds configuration for AuthService.
type AuthServiceConfig struct {
	PrivateKeyPath   string        // Path to RSA private key PEM file
	PublicKeyPath    string        // Path to RSA public key PEM file
	TokenTTL         time.Duration // Access token TTL
	RefreshTTL       time.Duration // Refresh token TTL
	MaxLoginAttempts int           // Max failed login attempts before lockout
	LockoutDuration  time.Duration // Duration of account lockout
	PasswordMaxAge   time.Duration // Max password age (0 = no expiration)
	DevMode          bool          // If true, generate keys if files don't exist
}

// DefaultAuthServiceConfig returns default configuration.
func DefaultAuthServiceConfig() AuthServiceConfig {
	return AuthServiceConfig{
		PrivateKeyPath:   "configs/keys/private.pem",
		PublicKeyPath:    "configs/keys/public.pem",
		TokenTTL:         15 * time.Minute,    // 15 minutes
		RefreshTTL:       7 * 24 * time.Hour,  // 7 days
		MaxLoginAttempts: 5,                   // 5 attempts
		LockoutDuration:  15 * time.Minute,    // 15 minutes
		PasswordMaxAge:   90 * 24 * time.Hour, // 90 days
		DevMode:          true,
	}
}

// NewAuthService creates a new AuthService instance.
// Loads RSA key pair from PEM files, or generates them in dev mode.
func NewAuthService(
	userRepo port.UserRepository,
	authz port.AuthorizationService,
	auditService port.AuditService,
	refreshCache port.RefreshTokenCache,
	tokenCache port.TokenCache,
	rateLimitCache port.RateLimitCache,
	config AuthServiceConfig,
	log *logger.Logger,
) (*AuthService, error) {
	componentLog := log.WithComponent("auth_service")

	var privateKey *rsa.PrivateKey
	var publicKey *rsa.PublicKey

	// Try to load keys from files
	privateKey, err := loadRSAPrivateKey(config.PrivateKeyPath)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, apperror.Internal("failed to load RSA private key", err)
		}

		// Key file doesn't exist
		if !config.DevMode {
			return nil, apperror.Internal("RSA key files not found and DevMode is disabled", err)
		}

		// Generate and save keys in dev mode
		componentLog.Info("RSA key files not found, generating new keys (dev mode)")
		privateKey, err = generateAndSaveKeys(config.PrivateKeyPath, config.PublicKeyPath)
		if err != nil {
			return nil, apperror.Internal("failed to generate and save RSA keys", err)
		}
		publicKey = &privateKey.PublicKey
	} else {
		// Load public key
		publicKey, err = loadRSAPublicKey(config.PublicKeyPath)
		if err != nil {
			return nil, apperror.Internal("failed to load RSA public key", err)
		}
		componentLog.Info("RSA keys loaded from files")
	}

	// Set default refresh TTL if not specified
	refreshTTL := config.RefreshTTL
	if refreshTTL == 0 {
		refreshTTL = 7 * 24 * time.Hour // 7 days
	}

	// Set default lockout config if not specified
	maxLoginAttempts := config.MaxLoginAttempts
	if maxLoginAttempts == 0 {
		maxLoginAttempts = 5 // Default 5 attempts
	}
	lockoutDuration := config.LockoutDuration
	if lockoutDuration == 0 {
		lockoutDuration = 15 * time.Minute // Default 15 minutes
	}

	// Password max age (0 means no expiration)
	passwordMaxAge := config.PasswordMaxAge

	return &AuthService{
		userRepo:         userRepo,
		authz:            authz,
		auditService:     auditService,
		refreshCache:     refreshCache,
		tokenCache:       tokenCache,
		rateLimitCache:   rateLimitCache,
		privateKey:       privateKey,
		publicKey:        publicKey,
		tokenTTL:         config.TokenTTL,
		refreshTTL:       refreshTTL,
		maxLoginAttempts: maxLoginAttempts,
		lockoutDuration:  lockoutDuration,
		passwordMaxAge:   passwordMaxAge,
		logger:           componentLog,
	}, nil
}

// loadRSAPrivateKey loads an RSA private key from a PEM file.
func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, apperror.Internal(fmt.Sprintf("failed to decode PEM block from %s", path), nil)
	}

	// Try PKCS#8 first, then PKCS#1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS#1
		pkcs1Key, pkcs1Err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if pkcs1Err != nil {
			return nil, apperror.Internal("failed to parse private key", pkcs1Err)
		}
		return pkcs1Key, nil
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, apperror.Internal("key is not RSA private key", nil)
	}
	return rsaKey, nil
}

// loadRSAPublicKey loads an RSA public key from a PEM file.
func loadRSAPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, apperror.Internal(fmt.Sprintf("failed to decode PEM block from %s", path), nil)
	}

	// Try PKIX first, then PKCS#1
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Fallback to PKCS#1
		pkcs1Key, pkcs1Err := x509.ParsePKCS1PublicKey(block.Bytes)
		if pkcs1Err != nil {
			return nil, apperror.Internal("failed to parse public key", pkcs1Err)
		}
		return pkcs1Key, nil
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, apperror.Internal("key is not RSA public key", nil)
	}
	return rsaKey, nil
}

// generateAndSaveKeys generates RSA key pair and saves to PEM files.
func generateAndSaveKeys(privatePath, publicPath string) (*rsa.PrivateKey, error) {
	// Generate key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Ensure directory exists
	err = os.MkdirAll(filepath.Dir(privatePath), 0o750)
	if err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Save private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(privatePath, privateKeyPEM, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to write private key: %w", err)
	}

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	// #nosec G306 -- public key is intended to be readable
	err = os.WriteFile(publicPath, publicKeyPEM, 0o644)
	if err != nil {
		return nil, fmt.Errorf("failed to write public key: %w", err)
	}

	return privateKey, nil
}

// Login authenticates a user and returns a JWT token pair.
//
// Returns: token pair, isOTP (true if one-time password), error.
func (s *AuthService) Login(ctx context.Context, email, password string) (tokens *port.TokenPair, isOTP bool, err error) {
	log := s.logger.WithContext(ctx)

	// Check if account is locked due to too many failed attempts
	lockoutKey := s.getLockoutKey(email)
	if locked, lockErr := s.isAccountLocked(ctx, lockoutKey); lockErr != nil {
		log.Warn("failed to check account lockout", "email", email, "error", lockErr)
	} else if locked {
		log.LogAuthAttempt(email, false, "account locked due to too many failed attempts")
		// Audit log: login attempt on locked account
		s.logAuditEvent(ctx, 0, domain.AuditActionLoginLocked, email, map[string]interface{}{
			"reason": "too_many_failed_attempts",
		})
		return nil, false, apperror.Unauthorized("account is temporarily locked due to too many failed login attempts")
	}

	// Find user by email
	user, err := s.userRepo.FindByEmail(ctx, email)
	if err != nil {
		// Increment failed attempts even for non-existent users to prevent enumeration
		s.recordFailedLoginAttempt(ctx, lockoutKey, email)
		log.LogAuthAttempt(email, false, "user not found")
		// Audit log: failed login (user not found)
		s.logAuditEvent(ctx, 0, domain.AuditActionLoginFailed, email, map[string]interface{}{
			"reason": "user_not_found",
		})
		// Return generic error to prevent user enumeration
		return nil, false, apperror.Unauthorized("invalid credentials")
	}

	// Check if user is blocked
	if user.IsBlocked {
		log.LogAuthAttempt(email, false, "user blocked")
		// Audit log: failed login (user blocked)
		s.logAuditEvent(ctx, user.ID, domain.AuditActionLoginFailed, email, map[string]interface{}{
			"reason": "user_blocked",
		})
		return nil, false, apperror.Unauthorized("user is blocked")
	}

	// Verify password
	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); bcryptErr != nil {
		s.recordFailedLoginAttempt(ctx, lockoutKey, email)
		log.LogAuthAttempt(email, false, "invalid password")
		// Audit log: failed login (invalid password)
		s.logAuditEvent(ctx, user.ID, domain.AuditActionLoginFailed, email, map[string]interface{}{
			"reason": "invalid_password",
		})
		return nil, false, apperror.Unauthorized("invalid credentials")
	}

	// Reset failed login attempts on successful authentication
	if resetErr := s.rateLimitCache.Reset(ctx, lockoutKey); resetErr != nil {
		log.Warn("failed to reset login attempts counter", "email", email, "error", resetErr)
	}

	// Check for one-time password
	if user.PasswordType == domain.PasswordTypeOneTime {
		log.LogAuthAttempt(email, true, "OTP login - password change required")
		// Audit log: OTP login success (requires password change)
		s.logAuditEvent(ctx, user.ID, domain.AuditActionLoginSuccess, email, map[string]interface{}{
			"otp_login":                true,
			"requires_password_change": true,
		})
		return nil, true, nil // Require password change
	}

	// Check for password expiration
	if s.isPasswordExpired(user) {
		log.LogAuthAttempt(email, true, "password expired - password change required")
		// Audit log: password expired
		s.logAuditEvent(ctx, user.ID, domain.AuditActionPasswordExpired, email, map[string]interface{}{
			"password_changed_at":      user.PasswordChangedAt,
			"requires_password_change": true,
		})
		return nil, false, apperror.PasswordExpired(user.ID)
	}

	// Get user roles
	roles, err := s.authz.GetUserRoles(ctx, user.ID)
	if err != nil {
		log.Error("failed to fetch user roles", "user_id", user.ID, "error", err)
		return nil, false, apperror.Internal("failed to fetch user permissions", err)
	}

	// Generate token pair
	tokens, err = s.generateTokenPair(ctx, user, roles)
	if err != nil {
		log.Error("failed to generate tokens", "user_id", user.ID, "error", err)
		return nil, false, apperror.Internal("failed to generate tokens", err)
	}

	// Audit log: successful login
	s.logAuditEvent(ctx, user.ID, domain.AuditActionLoginSuccess, email, map[string]interface{}{
		"roles": roles,
	})

	log.LogAuthAttempt(email, true, "login successful")
	return tokens, false, nil
}

// getLockoutKey generates a cache key for login attempt tracking.
func (s *AuthService) getLockoutKey(email string) string {
	return "login_attempts:" + email
}

// isAccountLocked checks if an account is locked due to too many failed attempts.
func (s *AuthService) isAccountLocked(ctx context.Context, lockoutKey string) (bool, error) {
	count, err := s.rateLimitCache.GetCount(ctx, lockoutKey)
	if err != nil {
		return false, err
	}
	return count >= int64(s.maxLoginAttempts), nil
}

// recordFailedLoginAttempt increments the failed login attempt counter.
func (s *AuthService) recordFailedLoginAttempt(ctx context.Context, lockoutKey, email string) {
	log := s.logger.WithContext(ctx)
	count, err := s.rateLimitCache.Increment(ctx, lockoutKey, s.lockoutDuration)
	if err != nil {
		log.Warn("failed to increment login attempts counter", "email", email, "error", err)
		return
	}
	if count >= int64(s.maxLoginAttempts) {
		log.Warn("account locked due to too many failed login attempts", "email", email, "attempts", count)
	}
}

// isPasswordExpired checks if the user's password has expired.
func (s *AuthService) isPasswordExpired(user *domain.User) bool {
	// If password max age is not set (0), passwords never expire
	if s.passwordMaxAge == 0 {
		return false
	}

	// If password changed at is not set, consider it expired (forces password change)
	if user.PasswordChangedAt == nil {
		return true
	}

	// Check if password has exceeded max age
	return time.Since(*user.PasswordChangedAt) > s.passwordMaxAge
}

// logAuditEvent logs an authentication event to the audit log.
func (s *AuthService) logAuditEvent(ctx context.Context, userID int64, action, resourceID string, details map[string]interface{}) {
	if s.auditService == nil {
		return
	}
	if err := s.auditService.LogAction(ctx, userID, action, domain.AuditResourceTypeAuth, resourceID, details); err != nil {
		s.logger.WithContext(ctx).Warn("failed to log audit event", "action", action, "error", err)
	}
}

// ValidateToken validates a JWT token and returns the claims.
func (s *AuthService) ValidateToken(_ context.Context, tokenString string) (*port.Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &port.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.publicKey, nil
	})

	if err != nil {
		return nil, apperror.Unauthorized("invalid token")
	}

	claims, ok := token.Claims.(*port.Claims)
	if !ok || !token.Valid {
		return nil, apperror.Unauthorized("invalid token")
	}

	return claims, nil
}

// ChangePassword changes the password for an authenticated user.
// Requires the old password for verification.
func (s *AuthService) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	log := s.logger.WithContext(ctx)

	// Find user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify old password
	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); bcryptErr != nil {
		return apperror.Unauthorized("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", "error", err)
		return apperror.Internal("failed to hash password", err)
	}

	// Update user
	now := time.Now()
	user.PasswordHash = string(hashedPassword)
	user.PasswordType = domain.PasswordTypePermanent
	user.PasswordChangedAt = &now
	user.UpdatedAt = now

	if err := s.userRepo.Update(ctx, user); err != nil {
		log.Error("failed to update password", "user_id", userID, "error", err)
		return err
	}

	// Audit log: password changed
	s.logAuditEvent(ctx, userID, domain.AuditActionPasswordChange, user.Email, map[string]interface{}{
		"email": user.Email,
	})

	log.Info("password changed successfully", "user_id", userID)
	return nil
}

// FirstTimePasswordChange changes the OTP password to a permanent one.
// Must be called when user logs in with one-time password.
func (s *AuthService) FirstTimePasswordChange(ctx context.Context, userID int64, oldPassword, newPassword string) error {
	log := s.logger.WithContext(ctx)

	// Find user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return err
	}

	// Verify this is actually a one-time password
	if user.PasswordType != domain.PasswordTypeOneTime {
		return apperror.BadRequest("this endpoint is only for one-time password changes")
	}

	// Check if user is blocked
	if user.IsBlocked {
		return apperror.Unauthorized("user is blocked")
	}

	// Verify old password
	if bcryptErr := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)); bcryptErr != nil {
		return apperror.Unauthorized("invalid old password")
	}

	// Hash new password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", "error", err)
		return apperror.Internal("failed to hash password", err)
	}

	// Update user
	now := time.Now()
	user.PasswordHash = string(hashedPassword)
	user.PasswordType = domain.PasswordTypePermanent
	user.PasswordChangedAt = &now
	user.UpdatedAt = now

	if err := s.userRepo.Update(ctx, user); err != nil {
		log.Error("failed to update password", "user_id", userID, "error", err)
		return err
	}

	// Audit log: first-time password changed
	s.logAuditEvent(ctx, userID, domain.AuditActionPasswordChangeFirstTime, user.Email, map[string]interface{}{
		"email":               user.Email,
		"previous_otp_status": true,
	})

	log.Info("first-time password changed successfully", "user_id", userID)
	return nil
}

// GetPublicKey returns the RSA public key for external token verification.
func (s *AuthService) GetPublicKey() interface{} {
	return s.publicKey
}

// generateAccessToken generates a JWT access token for a user.
func (s *AuthService) generateAccessToken(user *domain.User, roles []string) (string, error) {
	now := time.Now()

	// Generate unique JWT ID for blacklist support
	jti, err := s.generateJTI()
	if err != nil {
		return "", fmt.Errorf("failed to generate JTI: %w", err)
	}

	claims := port.Claims{
		UserID: user.ID,
		Email:  user.Email,
		Roles:  roles,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        jti,
			ExpiresAt: jwt.NewNumericDate(now.Add(s.tokenTTL)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "iam-service",
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(s.privateKey)
}

// generateJTI generates a unique JWT ID.
func (s *AuthService) generateJTI() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}

// generateRefreshToken generates a secure refresh token.
func (s *AuthService) generateRefreshToken() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate refresh token: %w", err)
	}
	return fmt.Sprintf("%x", bytes), nil
}

// generateTokenPair generates both access and refresh tokens.
func (s *AuthService) generateTokenPair(ctx context.Context, user *domain.User, roles []string) (*port.TokenPair, error) {
	// Generate access token
	accessToken, err := s.generateAccessToken(user, roles)
	if err != nil {
		return nil, err
	}

	// Generate refresh token
	refreshToken, err := s.generateRefreshToken()
	if err != nil {
		return nil, err
	}

	// Store refresh token in cache
	if err := s.refreshCache.StoreRefreshToken(ctx, refreshToken, user.ID, s.refreshTTL); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &port.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// RefreshToken validates refresh token and returns new access token.
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (string, error) {
	log := s.logger.WithContext(ctx)

	// Get user ID from refresh token
	userID, err := s.refreshCache.GetRefreshToken(ctx, refreshToken)
	if err != nil {
		log.Warn("refresh token not found or expired", "error", err)
		return "", apperror.Unauthorized("invalid or expired refresh token")
	}

	// Get user
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		log.Error("user not found for refresh token", "user_id", userID, "error", err)
		return "", apperror.Unauthorized("user not found")
	}

	// Check if user is blocked
	if user.IsBlocked {
		log.Warn("blocked user tried to refresh token", "user_id", userID)
		// Invalidate refresh token
		_ = s.refreshCache.DeleteRefreshToken(ctx, refreshToken)
		return "", apperror.Unauthorized("user is blocked")
	}

	// Get user roles
	roles, err := s.authz.GetUserRoles(ctx, userID)
	if err != nil {
		log.Error("failed to fetch user roles", "user_id", userID, "error", err)
		return "", apperror.Internal("failed to fetch user permissions", err)
	}

	// Generate new access token
	accessToken, err := s.generateAccessToken(user, roles)
	if err != nil {
		log.Error("failed to generate access token", "user_id", userID, "error", err)
		return "", apperror.Internal("failed to generate token", err)
	}

	log.Info("token refreshed successfully", "user_id", userID)
	return accessToken, nil
}

// Logout invalidates a refresh token and optionally blacklists an access token.
func (s *AuthService) Logout(ctx context.Context, refreshToken, accessToken string) error {
	log := s.logger.WithContext(ctx)

	// Get userID from refresh token before deleting (for audit log)
	userID, _ := s.refreshCache.GetRefreshToken(ctx, refreshToken)

	// Delete refresh token
	if err := s.refreshCache.DeleteRefreshToken(ctx, refreshToken); err != nil {
		log.Error("failed to delete refresh token", "error", err)
		return apperror.Internal("failed to logout", err)
	}

	// Blacklist access token if provided
	if accessToken != "" {
		if err := s.blacklistAccessToken(ctx, accessToken); err != nil {
			log.Warn("failed to blacklist access token", "error", err)
			// Don't fail logout if blacklisting fails
		}
	}

	// Audit log: logout
	s.logAuditEvent(ctx, userID, domain.AuditActionLogout, fmt.Sprintf("%d", userID), map[string]interface{}{
		"access_token_blacklisted": accessToken != "",
	})

	log.Info("user logged out successfully")
	return nil
}

// blacklistAccessToken adds an access token to the blacklist.
func (s *AuthService) blacklistAccessToken(ctx context.Context, tokenString string) error {
	// Parse token to get JTI and expiration
	claims, err := s.ValidateToken(ctx, tokenString)
	if err != nil {
		return fmt.Errorf("failed to parse token for blacklisting: %w", err)
	}

	// Get JTI from claims
	if claims.ID == "" {
		return apperror.BadRequest("token has no JTI, cannot blacklist")
	}

	// Calculate remaining TTL
	var ttl time.Duration
	if claims.ExpiresAt != nil {
		ttl = time.Until(claims.ExpiresAt.Time)
		if ttl <= 0 {
			// Token already expired, no need to blacklist
			return nil
		}
	} else {
		// No expiration, use default token TTL
		ttl = s.tokenTTL
	}

	// Add to blacklist
	return s.tokenCache.BlacklistToken(ctx, claims.ID, ttl)
}

// LogoutAll invalidates all refresh tokens for a user and blacklists current access token.
func (s *AuthService) LogoutAll(ctx context.Context, userID int64, accessToken string) error {
	log := s.logger.WithContext(ctx)

	// Delete all refresh tokens
	if err := s.refreshCache.DeleteUserRefreshTokens(ctx, userID); err != nil {
		log.Error("failed to delete user refresh tokens", "user_id", userID, "error", err)
		return apperror.Internal("failed to logout from all devices", err)
	}

	// Blacklist current access token if provided
	if accessToken != "" {
		if err := s.blacklistAccessToken(ctx, accessToken); err != nil {
			log.Warn("failed to blacklist access token", "error", err)
			// Don't fail logout if blacklisting fails
		}
	}

	// Audit log: logout from all devices
	s.logAuditEvent(ctx, userID, domain.AuditActionLogoutAll, fmt.Sprintf("%d", userID), map[string]interface{}{
		"access_token_blacklisted": accessToken != "",
	})

	log.Info("user logged out from all devices", "user_id", userID)
	return nil
}

// IsTokenBlacklisted checks if a token is in the blacklist.
func (s *AuthService) IsTokenBlacklisted(ctx context.Context, jti string) (bool, error) {
	return s.tokenCache.IsBlacklisted(ctx, jti)
}

// GenerateTokenForUser generates a token pair for a user by ID.
// Used after first-time password change.
func (s *AuthService) GenerateTokenForUser(ctx context.Context, userID int64) (*port.TokenPair, error) {
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	roles, err := s.authz.GetUserRoles(ctx, userID)
	if err != nil {
		return nil, apperror.Internal("failed to fetch user permissions", err)
	}

	return s.generateTokenPair(ctx, user, roles)
}

// GetUserByEmail retrieves a user by email.
// Used for OTP flow.
func (s *AuthService) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

// GetUserSessions retrieves all active sessions for a user.
// Returns a list of sessions with their metadata.
func (s *AuthService) GetUserSessions(ctx context.Context, userID int64, currentTokenID string) ([]domain.Session, error) {
	log := s.logger.WithContext(ctx)

	// Get all refresh tokens for the user with their TTLs
	tokens, err := s.refreshCache.GetUserTokens(ctx, userID)
	if err != nil {
		log.Error("failed to get user tokens", "user_id", userID, "error", err)
		return nil, apperror.Internal("failed to get user sessions", err)
	}

	sessions := make([]domain.Session, 0, len(tokens))
	now := time.Now()

	for tokenID, ttlSeconds := range tokens {
		expiresAt := now.Add(time.Duration(ttlSeconds) * time.Second)
		// Approximate creation time based on refresh TTL and remaining TTL
		createdAt := expiresAt.Add(-s.refreshTTL)

		session := domain.Session{
			ID:        tokenID[:8], // Short ID for display
			TokenID:   tokenID,
			CreatedAt: createdAt,
			ExpiresAt: expiresAt,
			IsCurrent: tokenID == currentTokenID,
		}
		sessions = append(sessions, session)
	}

	log.Info("retrieved user sessions", "user_id", userID, "count", len(sessions))
	return sessions, nil
}

// RevokeSession revokes a specific session by its token ID.
func (s *AuthService) RevokeSession(ctx context.Context, userID int64, tokenID string) error {
	log := s.logger.WithContext(ctx)

	// Verify the token belongs to this user
	tokenUserID, err := s.refreshCache.GetRefreshToken(ctx, tokenID)
	if err != nil {
		log.Warn("session not found for revocation", "user_id", userID, "token_id", tokenID[:8])
		return apperror.NotFound("session", tokenID[:8])
	}

	if tokenUserID != userID {
		log.Warn("attempted to revoke session belonging to another user", "user_id", userID, "token_user_id", tokenUserID)
		return apperror.Forbidden("cannot revoke sessions of other users")
	}

	// Delete the refresh token
	if err := s.refreshCache.DeleteRefreshToken(ctx, tokenID); err != nil {
		log.Error("failed to revoke session", "user_id", userID, "token_id", tokenID[:8], "error", err)
		return apperror.Internal("failed to revoke session", err)
	}

	// Audit log: session revoked
	s.logAuditEvent(ctx, userID, domain.AuditActionSessionRevoke, tokenID[:8], map[string]interface{}{
		"token_id_prefix": tokenID[:8],
	})

	log.Info("session revoked successfully", "user_id", userID, "token_id", tokenID[:8])
	return nil
}
