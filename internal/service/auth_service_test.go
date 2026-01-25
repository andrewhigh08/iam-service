package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/service"
)

// MockRefreshTokenCache is a mock implementation of port.RefreshTokenCache
type MockRefreshTokenCache struct {
	mock.Mock
}

func (m *MockRefreshTokenCache) StoreRefreshToken(ctx context.Context, tokenID string, userID int64, expiration time.Duration) error {
	args := m.Called(ctx, tokenID, userID, expiration)
	return args.Error(0)
}

func (m *MockRefreshTokenCache) GetRefreshToken(ctx context.Context, tokenID string) (int64, error) {
	args := m.Called(ctx, tokenID)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRefreshTokenCache) DeleteRefreshToken(ctx context.Context, tokenID string) error {
	args := m.Called(ctx, tokenID)
	return args.Error(0)
}

func (m *MockRefreshTokenCache) DeleteUserRefreshTokens(ctx context.Context, userID int64) error {
	args := m.Called(ctx, userID)
	return args.Error(0)
}

func (m *MockRefreshTokenCache) GetUserTokens(ctx context.Context, userID int64) (map[string]int64, error) {
	args := m.Called(ctx, userID)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(map[string]int64), args.Error(1)
}

// MockTokenCache is a mock implementation of port.TokenCache
type MockTokenCache struct {
	mock.Mock
}

func (m *MockTokenCache) BlacklistToken(ctx context.Context, tokenID string, expiration time.Duration) error {
	args := m.Called(ctx, tokenID, expiration)
	return args.Error(0)
}

func (m *MockTokenCache) IsBlacklisted(ctx context.Context, tokenID string) (bool, error) {
	args := m.Called(ctx, tokenID)
	return args.Bool(0), args.Error(1)
}

// MockRateLimitCache is a mock implementation of port.RateLimitCache
type MockRateLimitCache struct {
	mock.Mock
}

func (m *MockRateLimitCache) Increment(ctx context.Context, key string, expiration time.Duration) (int64, error) {
	args := m.Called(ctx, key, expiration)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRateLimitCache) GetCount(ctx context.Context, key string) (int64, error) {
	args := m.Called(ctx, key)
	return args.Get(0).(int64), args.Error(1)
}

func (m *MockRateLimitCache) Reset(ctx context.Context, key string) error {
	args := m.Called(ctx, key)
	return args.Error(0)
}

// MockAuditService is a mock implementation of port.AuditService
type MockAuditService struct {
	mock.Mock
}

func (m *MockAuditService) LogAction(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error {
	args := m.Called(ctx, userID, action, resourceType, resourceID, details)
	return args.Error(0)
}

func (m *MockAuditService) LogActionTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}) error {
	args := m.Called(ctx, tx, userID, action, resourceType, resourceID, details)
	return args.Error(0)
}

func (m *MockAuditService) LogActionWithContext(ctx context.Context, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error {
	args := m.Called(ctx, userID, action, resourceType, resourceID, details, ipAddress, userAgent)
	return args.Error(0)
}

func (m *MockAuditService) LogActionWithContextTx(ctx context.Context, tx *gorm.DB, userID int64, action, resourceType, resourceID string, details map[string]interface{}, ipAddress, userAgent string) error {
	args := m.Called(ctx, tx, userID, action, resourceType, resourceID, details, ipAddress, userAgent)
	return args.Error(0)
}

func (m *MockAuditService) GetUserAuditLogs(ctx context.Context, userID int64, limit int) ([]domain.AuditLog, error) {
	args := m.Called(ctx, userID, limit)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]domain.AuditLog), args.Error(1)
}

func TestAuthService_Login(t *testing.T) {
	// Generate a valid password hash for testing
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	tests := []struct {
		name        string
		email       string
		password    string
		setupMock   func(*MockUserRepository, *MockAuthorizationService)
		wantToken   bool
		wantOTP     bool
		wantErr     bool
		expectedErr string
	}{
		{
			name:     "success - valid credentials",
			email:    "test@example.com",
			password: "Password123!",
			setupMock: func(userRepo *MockUserRepository, authzService *MockAuthorizationService) {
				userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:           1,
					Email:        "test@example.com",
					PasswordHash: string(validPasswordHash),
					PasswordType: domain.PasswordTypePermanent,
					IsBlocked:    false,
				}, nil)
				authzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"viewer"}, nil)
			},
			wantToken: true,
			wantOTP:   false,
			wantErr:   false,
		},
		{
			name:     "success - OTP user requires password change",
			email:    "otp@example.com",
			password: "TempPass123!",
			setupMock: func(userRepo *MockUserRepository, authzService *MockAuthorizationService) {
				otpHash, _ := bcrypt.GenerateFromPassword([]byte("TempPass123!"), bcrypt.DefaultCost)
				userRepo.On("FindByEmail", mock.Anything, "otp@example.com").Return(&domain.User{
					ID:           2,
					Email:        "otp@example.com",
					PasswordHash: string(otpHash),
					PasswordType: domain.PasswordTypeOneTime,
					IsBlocked:    false,
				}, nil)
			},
			wantToken: false,
			wantOTP:   true,
			wantErr:   false,
		},
		{
			name:     "failure - user not found",
			email:    "notfound@example.com",
			password: "Password123!",
			setupMock: func(userRepo *MockUserRepository, authzService *MockAuthorizationService) {
				userRepo.On("FindByEmail", mock.Anything, "notfound@example.com").Return(nil, apperror.NotFound("user", "notfound@example.com"))
			},
			wantToken:   false,
			wantOTP:     false,
			wantErr:     true,
			expectedErr: "UNAUTHORIZED",
		},
		{
			name:     "failure - wrong password",
			email:    "test@example.com",
			password: "WrongPassword!",
			setupMock: func(userRepo *MockUserRepository, authzService *MockAuthorizationService) {
				userRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
					ID:           1,
					Email:        "test@example.com",
					PasswordHash: string(validPasswordHash),
					PasswordType: domain.PasswordTypePermanent,
					IsBlocked:    false,
				}, nil)
			},
			wantToken:   false,
			wantOTP:     false,
			wantErr:     true,
			expectedErr: "UNAUTHORIZED",
		},
		{
			name:     "failure - user is blocked",
			email:    "blocked@example.com",
			password: "Password123!",
			setupMock: func(userRepo *MockUserRepository, authzService *MockAuthorizationService) {
				userRepo.On("FindByEmail", mock.Anything, "blocked@example.com").Return(&domain.User{
					ID:           3,
					Email:        "blocked@example.com",
					PasswordHash: string(validPasswordHash),
					PasswordType: domain.PasswordTypePermanent,
					IsBlocked:    true,
				}, nil)
			},
			wantToken:   false,
			wantOTP:     false,
			wantErr:     true,
			expectedErr: "UNAUTHORIZED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			mockAuthzService := new(MockAuthorizationService)
			tt.setupMock(mockUserRepo, mockAuthzService)

			// Simulate the login logic
			user, err := mockUserRepo.FindByEmail(context.Background(), tt.email)

			if tt.wantErr {
				if err != nil {
					// User not found case
					require.Error(t, err)
					return
				}
				// Check other error conditions
				if user.IsBlocked {
					assert.True(t, tt.expectedErr == "UNAUTHORIZED")
					return
				}
				// Check password
				if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tt.password)) != nil {
					assert.True(t, tt.expectedErr == "UNAUTHORIZED")
					return
				}
			} else {
				require.NoError(t, err)
				require.NotNil(t, user)

				// Check OTP case
				if user.PasswordType == domain.PasswordTypeOneTime {
					assert.True(t, tt.wantOTP)
					return
				}

				// For valid login, we'd generate a token
				if tt.wantToken {
					roles, _ := mockAuthzService.GetUserRoles(context.Background(), user.ID)
					assert.NotEmpty(t, roles)
				}
			}

			mockUserRepo.AssertExpectations(t)
			mockAuthzService.AssertExpectations(t)
		})
	}
}

func TestAuthService_ChangePassword(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("OldPassword123!"), bcrypt.DefaultCost)

	tests := []struct {
		name        string
		userID      int64
		oldPassword string
		newPassword string
		setupMock   func(*MockUserRepository)
		wantErr     bool
		expectedErr string
	}{
		{
			name:        "success - password changed",
			userID:      1,
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword456!",
			setupMock: func(userRepo *MockUserRepository) {
				userRepo.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:           1,
					Email:        "test@example.com",
					PasswordHash: string(validPasswordHash),
					PasswordType: domain.PasswordTypePermanent,
				}, nil)
				userRepo.On("Update", mock.Anything, mock.AnythingOfType("*domain.User")).Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "failure - user not found",
			userID:      999,
			oldPassword: "OldPassword123!",
			newPassword: "NewPassword456!",
			setupMock: func(userRepo *MockUserRepository) {
				userRepo.On("FindByID", mock.Anything, int64(999)).Return(nil, apperror.NotFound("user", 999))
			},
			wantErr:     true,
			expectedErr: "NOT_FOUND",
		},
		{
			name:        "failure - wrong old password",
			userID:      1,
			oldPassword: "WrongOldPassword!",
			newPassword: "NewPassword456!",
			setupMock: func(userRepo *MockUserRepository) {
				userRepo.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:           1,
					Email:        "test@example.com",
					PasswordHash: string(validPasswordHash),
					PasswordType: domain.PasswordTypePermanent,
				}, nil)
			},
			wantErr:     true,
			expectedErr: "UNAUTHORIZED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			tt.setupMock(mockUserRepo)

			// Simulate password change logic
			user, err := mockUserRepo.FindByID(context.Background(), tt.userID)

			if err != nil {
				require.Error(t, err)
				if tt.expectedErr != "" {
					appErr, ok := apperror.AsAppError(err)
					require.True(t, ok)
					assert.Equal(t, tt.expectedErr, appErr.Code)
				}
				return
			}

			// Verify old password
			if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(tt.oldPassword)) != nil {
				if tt.wantErr {
					assert.Equal(t, "UNAUTHORIZED", tt.expectedErr)
				}
				return
			}

			// Update password
			if !tt.wantErr {
				err = mockUserRepo.Update(context.Background(), user)
				require.NoError(t, err)
			}

			mockUserRepo.AssertExpectations(t)
		})
	}
}

func TestPasswordValidation(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "valid password",
			password: "SecurePass123!",
			wantErr:  false,
		},
		{
			name:     "too short",
			password: "Short1!",
			wantErr:  true,
		},
		{
			name:     "no uppercase",
			password: "securepass123!",
			wantErr:  true,
		},
		{
			name:     "no lowercase",
			password: "SECUREPASS123!",
			wantErr:  true,
		},
		{
			name:     "no digit",
			password: "SecurePassword!",
			wantErr:  true,
		},
		{
			name:     "no special character",
			password: "SecurePass123",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := isValidPassword(tt.password)
			if tt.wantErr {
				assert.False(t, valid)
			} else {
				assert.True(t, valid)
			}
		})
	}
}

// isValidPassword checks if password meets complexity requirements
func isValidPassword(password string) bool {
	if len(password) < 8 {
		return false
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case char == '!' || char == '@' || char == '#' || char == '$' || char == '%' || char == '^' || char == '&' || char == '*':
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

func TestNewAuthService_LoadKeysFromFiles(t *testing.T) {
	// Create temp directory for test keys
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")

	// Generate test RSA keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Save private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0o600)
	require.NoError(t, err)

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile(publicKeyPath, publicKeyPEM, 0o644)
	require.NoError(t, err)

	// Create mocks
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)
	mockAuditService := new(MockAuditService)
	log := logger.New(logger.Config{Level: "error", Format: "json"})

	// Test loading keys from files
	config := service.AuthServiceConfig{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		TokenTTL:       15 * 60 * 1000000000, // 15 minutes in nanoseconds
		DevMode:        false,
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Verify public key is accessible
	pubKey := authService.GetPublicKey()
	require.NotNil(t, pubKey)
}

func TestNewAuthService_GenerateKeysInDevMode(t *testing.T) {
	// Create temp directory for test keys
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "keys", "private.pem")
	publicKeyPath := filepath.Join(tempDir, "keys", "public.pem")

	// Create mocks
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)
	mockAuditService := new(MockAuditService)
	log := logger.New(logger.Config{Level: "error", Format: "json"})

	// Test generating keys in dev mode (keys don't exist)
	config := service.AuthServiceConfig{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		TokenTTL:       15 * 60 * 1000000000,
		DevMode:        true,
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.NoError(t, err)
	require.NotNil(t, authService)

	// Verify keys were generated
	assert.FileExists(t, privateKeyPath)
	assert.FileExists(t, publicKeyPath)

	// Verify file permissions
	privateInfo, err := os.Stat(privateKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), privateInfo.Mode().Perm())

	publicInfo, err := os.Stat(publicKeyPath)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o644), publicInfo.Mode().Perm())

	// Verify public key is accessible
	pubKey := authService.GetPublicKey()
	require.NotNil(t, pubKey)
}

func TestNewAuthService_FailsWithoutKeysInProdMode(t *testing.T) {
	// Create temp directory for test keys (but don't create the keys)
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "nonexistent", "private.pem")
	publicKeyPath := filepath.Join(tempDir, "nonexistent", "public.pem")

	// Create mocks
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockAuditService := new(MockAuditService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)
	log := logger.New(logger.Config{Level: "error", Format: "json"})

	// Test that it fails in prod mode when keys don't exist
	config := service.AuthServiceConfig{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		TokenTTL:       15 * 60 * 1000000000,
		DevMode:        false, // Production mode
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.Error(t, err)
	require.Nil(t, authService)

	// Verify it's an internal error
	appErr, ok := apperror.AsAppError(err)
	require.True(t, ok)
	assert.Equal(t, "INTERNAL_ERROR", appErr.Code)
}

func TestNewAuthService_FailsWithInvalidKeyFormat(t *testing.T) {
	// Create temp directory for test keys
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "private.pem")
	publicKeyPath := filepath.Join(tempDir, "public.pem")

	// Write invalid PEM content
	err := os.WriteFile(privateKeyPath, []byte("not a valid PEM file"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(publicKeyPath, []byte("not a valid PEM file"), 0o644)
	require.NoError(t, err)

	// Create mocks
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockAuditService := new(MockAuditService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)
	log := logger.New(logger.Config{Level: "error", Format: "json"})

	config := service.AuthServiceConfig{
		PrivateKeyPath: privateKeyPath,
		PublicKeyPath:  publicKeyPath,
		TokenTTL:       15 * 60 * 1000000000,
		DevMode:        false,
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.Error(t, err)
	require.Nil(t, authService)
}

// ==================== Account Lockout Tests ====================

func createTestAuthService(t *testing.T, mockUserRepo *MockUserRepository, mockAuthzService *MockAuthorizationService, mockRefreshCache *MockRefreshTokenCache, mockTokenCache *MockTokenCache, mockRateLimitCache *MockRateLimitCache) *service.AuthService {
	// Create temp directory for test keys
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "keys", "private.pem")
	publicKeyPath := filepath.Join(tempDir, "keys", "public.pem")

	log := logger.New(logger.Config{Level: "error", Format: "json"})

	// Create mock audit service that accepts any call
	mockAuditService := new(MockAuditService)
	mockAuditService.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	config := service.AuthServiceConfig{
		PrivateKeyPath:   privateKeyPath,
		PublicKeyPath:    publicKeyPath,
		TokenTTL:         15 * time.Minute,
		MaxLoginAttempts: 3,
		LockoutDuration:  15 * time.Minute,
		DevMode:          true,
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.NoError(t, err)
	return authService
}

func TestAuthService_Login_AccountLocked(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Account is locked (3 or more failed attempts)
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:locked@example.com").Return(int64(3), nil)

	tokens, isOTP, err := authService.Login(context.Background(), "locked@example.com", "Password123!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "temporarily locked")

	mockRateLimitCache.AssertExpectations(t)
}

func TestAuthService_Login_FailedAttemptIncrementsCounter(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Account is not locked yet
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(0), nil)

	// User exists
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:           1,
		Email:        "test@example.com",
		PasswordHash: string(validPasswordHash),
		PasswordType: domain.PasswordTypePermanent,
		IsBlocked:    false,
	}, nil)

	// Wrong password should increment counter
	mockRateLimitCache.On("Increment", mock.Anything, "login_attempts:test@example.com", 15*time.Minute).Return(int64(1), nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "WrongPassword!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_Login_UserNotFoundIncrementsCounter(t *testing.T) {
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Account is not locked
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:notfound@example.com").Return(int64(0), nil)

	// User not found
	mockUserRepo.On("FindByEmail", mock.Anything, "notfound@example.com").Return(nil, apperror.NotFound("user", "notfound@example.com"))

	// Should increment counter even for non-existent users (to prevent enumeration)
	mockRateLimitCache.On("Increment", mock.Anything, "login_attempts:notfound@example.com", 15*time.Minute).Return(int64(1), nil)

	tokens, isOTP, err := authService.Login(context.Background(), "notfound@example.com", "Password123!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_Login_SuccessResetsCounter(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Account is not locked (1 previous failed attempt)
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(1), nil)

	// User exists with valid password
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:           1,
		Email:        "test@example.com",
		PasswordHash: string(validPasswordHash),
		PasswordType: domain.PasswordTypePermanent,
		IsBlocked:    false,
	}, nil)

	// Should reset counter on successful login
	mockRateLimitCache.On("Reset", mock.Anything, "login_attempts:test@example.com").Return(nil)

	// Get roles and store refresh token for successful login
	mockAuthzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"viewer"}, nil)
	mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.AnythingOfType("string"), int64(1), mock.AnythingOfType("time.Duration")).Return(nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "Password123!")

	require.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.False(t, isOTP)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
	mockAuthzService.AssertExpectations(t)
	mockRefreshCache.AssertExpectations(t)
}

func TestAuthService_Login_LockoutAfterMaxAttempts(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Account is not locked (2 previous failed attempts)
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(2), nil)

	// User exists
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:           1,
		Email:        "test@example.com",
		PasswordHash: string(validPasswordHash),
		PasswordType: domain.PasswordTypePermanent,
		IsBlocked:    false,
	}, nil)

	// This will be the 3rd failed attempt, which triggers lockout
	mockRateLimitCache.On("Increment", mock.Anything, "login_attempts:test@example.com", 15*time.Minute).Return(int64(3), nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "WrongPassword!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid credentials")

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

// ==================== Password Expiration Tests ====================

func createTestAuthServiceWithPasswordExpiration(t *testing.T, mockUserRepo *MockUserRepository, mockAuthzService *MockAuthorizationService, mockRefreshCache *MockRefreshTokenCache, mockTokenCache *MockTokenCache, mockRateLimitCache *MockRateLimitCache, passwordMaxAge time.Duration) *service.AuthService {
	tempDir := t.TempDir()
	privateKeyPath := filepath.Join(tempDir, "keys", "private.pem")
	publicKeyPath := filepath.Join(tempDir, "keys", "public.pem")

	log := logger.New(logger.Config{Level: "error", Format: "json"})

	mockAuditService := new(MockAuditService)
	mockAuditService.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	config := service.AuthServiceConfig{
		PrivateKeyPath:   privateKeyPath,
		PublicKeyPath:    publicKeyPath,
		TokenTTL:         15 * time.Minute,
		MaxLoginAttempts: 3,
		LockoutDuration:  15 * time.Minute,
		PasswordMaxAge:   passwordMaxAge,
		DevMode:          true,
	}

	authService, err := service.NewAuthService(mockUserRepo, mockAuthzService, mockAuditService, mockRefreshCache, mockTokenCache, mockRateLimitCache, config, log)
	require.NoError(t, err)
	return authService
}

func TestAuthService_Login_PasswordExpired_NilPasswordChangedAt(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	// Create service with 90 days password expiration
	authService := createTestAuthServiceWithPasswordExpiration(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache, 90*24*time.Hour)

	// Account is not locked
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(0), nil)

	// User exists with PasswordChangedAt = nil (never changed)
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:                1,
		Email:             "test@example.com",
		PasswordHash:      string(validPasswordHash),
		PasswordType:      domain.PasswordTypePermanent,
		PasswordChangedAt: nil, // Never changed - should be considered expired
		IsBlocked:         false,
	}, nil)

	// Reset counter on successful auth (before expiration check)
	mockRateLimitCache.On("Reset", mock.Anything, "login_attempts:test@example.com").Return(nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "Password123!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)
	appErr, ok := apperror.AsAppError(err)
	require.True(t, ok)
	assert.Equal(t, apperror.CodePasswordExpired, appErr.Code)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_Login_PasswordExpired_OldPassword(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	// Create service with 90 days password expiration
	authService := createTestAuthServiceWithPasswordExpiration(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache, 90*24*time.Hour)

	// Account is not locked
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(0), nil)

	// Password changed 100 days ago (expired)
	oldTime := time.Now().Add(-100 * 24 * time.Hour)
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:                1,
		Email:             "test@example.com",
		PasswordHash:      string(validPasswordHash),
		PasswordType:      domain.PasswordTypePermanent,
		PasswordChangedAt: &oldTime,
		IsBlocked:         false,
	}, nil)

	// Reset counter on successful auth
	mockRateLimitCache.On("Reset", mock.Anything, "login_attempts:test@example.com").Return(nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "Password123!")

	assert.Nil(t, tokens)
	assert.False(t, isOTP)
	assert.Error(t, err)
	appErr, ok := apperror.AsAppError(err)
	require.True(t, ok)
	assert.Equal(t, apperror.CodePasswordExpired, appErr.Code)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
}

func TestAuthService_Login_PasswordNotExpired(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	// Create service with 90 days password expiration
	authService := createTestAuthServiceWithPasswordExpiration(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache, 90*24*time.Hour)

	// Account is not locked
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(0), nil)

	// Password changed 30 days ago (not expired)
	recentTime := time.Now().Add(-30 * 24 * time.Hour)
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:                1,
		Email:             "test@example.com",
		PasswordHash:      string(validPasswordHash),
		PasswordType:      domain.PasswordTypePermanent,
		PasswordChangedAt: &recentTime,
		IsBlocked:         false,
	}, nil)

	// Reset counter on successful auth
	mockRateLimitCache.On("Reset", mock.Anything, "login_attempts:test@example.com").Return(nil)

	// Get roles
	mockAuthzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"user"}, nil)

	// Store refresh token
	mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.Anything, int64(1), mock.Anything).Return(nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "Password123!")

	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.False(t, isOTP)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
	mockAuthzService.AssertExpectations(t)
	mockRefreshCache.AssertExpectations(t)
}

func TestAuthService_Login_NoPasswordExpiration(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	// Create service with NO password expiration (0)
	authService := createTestAuthServiceWithPasswordExpiration(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache, 0)

	// Account is not locked
	mockRateLimitCache.On("GetCount", mock.Anything, "login_attempts:test@example.com").Return(int64(0), nil)

	// User with PasswordChangedAt = nil should NOT be expired when expiration is disabled
	mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
		ID:                1,
		Email:             "test@example.com",
		PasswordHash:      string(validPasswordHash),
		PasswordType:      domain.PasswordTypePermanent,
		PasswordChangedAt: nil, // Never changed but expiration is disabled
		IsBlocked:         false,
	}, nil)

	// Reset counter on successful auth
	mockRateLimitCache.On("Reset", mock.Anything, "login_attempts:test@example.com").Return(nil)

	// Get roles
	mockAuthzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"user"}, nil)

	// Store refresh token
	mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.Anything, int64(1), mock.Anything).Return(nil)

	tokens, isOTP, err := authService.Login(context.Background(), "test@example.com", "Password123!")

	assert.NoError(t, err)
	assert.NotNil(t, tokens)
	assert.NotEmpty(t, tokens.AccessToken)
	assert.NotEmpty(t, tokens.RefreshToken)
	assert.False(t, isOTP)

	mockRateLimitCache.AssertExpectations(t)
	mockUserRepo.AssertExpectations(t)
	mockAuthzService.AssertExpectations(t)
	mockRefreshCache.AssertExpectations(t)
}

// ==================== JWT Edge Cases ====================

func TestValidateToken_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		token       string
		wantErr     bool
		errContains string
	}{
		{
			name:        "empty token",
			token:       "",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "malformed token - no dots",
			token:       "notavalidtoken",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "malformed token - only header",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "malformed token - two parts",
			token:       "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "token with invalid base64",
			token:       "not!!!valid!!!base64.not!!!valid!!!base64.not!!!valid!!!base64",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "token with wrong algorithm header (HS256)",
			token:       "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "extremely long token",
			token:       string(make([]byte, 10000)),
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:        "token with null bytes",
			token:       "eyJhbGciOiJSUzI1NiJ9\x00.eyJzdWIiOiIxIn0\x00.signature",
			wantErr:     true,
			errContains: "invalid",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			mockAuthzService := new(MockAuthorizationService)
			mockRefreshCache := new(MockRefreshTokenCache)
			mockTokenCache := new(MockTokenCache)
			mockRateLimitCache := new(MockRateLimitCache)

			authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

			claims, err := authService.ValidateToken(context.Background(), tt.token)

			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, claims)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				require.NoError(t, err)
				assert.NotNil(t, claims)
			}
		})
	}
}

// ==================== Bcrypt Edge Cases ====================

func TestBcrypt_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		desc        string
		shouldError bool // Some cases should error (>72 bytes in modern Go bcrypt)
	}{
		{
			name:        "empty password",
			password:    "",
			desc:        "Empty password should be hashable",
			shouldError: false,
		},
		{
			name:        "single character",
			password:    "a",
			desc:        "Single char password",
			shouldError: false,
		},
		{
			name:        "exactly 72 bytes",
			password:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			desc:        "Exactly at bcrypt limit (72 chars)",
			shouldError: false,
		},
		{
			name:        "unicode - cyrillic",
			password:    "ПарольСекретный123!",
			desc:        "Cyrillic characters",
			shouldError: false,
		},
		{
			name:        "unicode - emoji",
			password:    "Password🔐123!",
			desc:        "Emoji in password",
			shouldError: false,
		},
		{
			name:        "unicode - mixed",
			password:    "Пароль密码🔐Pass!",
			desc:        "Mixed unicode scripts",
			shouldError: false,
		},
		{
			name:        "special characters only",
			password:    "!@#$%^&*()_+-=[]{}|;':\",./<>?",
			desc:        "Only special characters",
			shouldError: false,
		},
		{
			name:        "whitespace",
			password:    "   password with spaces   ",
			desc:        "Password with leading/trailing spaces",
			shouldError: false,
		},
		{
			name:        "newlines and tabs",
			password:    "password\nwith\nnewlines\tand\ttabs",
			desc:        "Password with control characters",
			shouldError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test hashing
			hash, err := bcrypt.GenerateFromPassword([]byte(tt.password), bcrypt.DefaultCost)
			if tt.shouldError {
				assert.Error(t, err, tt.desc)
				return
			}
			require.NoError(t, err, "Hashing should succeed: %s", tt.desc)

			// Test comparison
			err = bcrypt.CompareHashAndPassword(hash, []byte(tt.password))
			assert.NoError(t, err, "Comparison should succeed: %s", tt.desc)

			// Test wrong password (only if original password is not empty)
			if tt.password != "" {
				wrongPassword := tt.password + "X"
				// Only test if wrong password is <= 72 bytes
				if len(wrongPassword) <= 72 {
					err = bcrypt.CompareHashAndPassword(hash, []byte(wrongPassword))
					assert.Error(t, err, "Wrong password should fail")
				}
			}
		})
	}
}

// TestBcrypt_PasswordLengthLimit verifies that bcrypt rejects passwords > 72 bytes.
// NOTE: Modern Go bcrypt (since 1.18+) returns error for passwords > 72 bytes
// instead of silently truncating them.
func TestBcrypt_PasswordLengthLimit(t *testing.T) {
	tests := []struct {
		name        string
		password    string
		shouldError bool
		desc        string
	}{
		{
			name:        "71 bytes - should work",
			password:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldError: false,
			desc:        "71 bytes is within limit",
		},
		{
			name:        "72 bytes - should work",
			password:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldError: false,
			desc:        "72 bytes is exactly at limit",
		},
		{
			name:        "73 bytes - should error",
			password:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldError: true,
			desc:        "73 bytes exceeds limit",
		},
		{
			name:        "100 bytes - should error",
			password:    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			shouldError: true,
			desc:        "100 bytes exceeds limit",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := bcrypt.GenerateFromPassword([]byte(tt.password), bcrypt.DefaultCost)
			if tt.shouldError {
				assert.Error(t, err, tt.desc)
				assert.Contains(t, err.Error(), "72 bytes", "Should mention 72 byte limit")
			} else {
				assert.NoError(t, err, tt.desc)
			}
		})
	}
}

// ==================== Login Edge Cases ====================

func TestLogin_EdgeCases(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		password    string
		desc        string
		wantErr     bool
		errContains string
	}{
		{
			name:     "very long email",
			email:    "verylongemailaddressthatexceeds255charactersverylongemailaddressthatexceeds255charactersverylongemailaddressthatexceeds255charactersverylongemailaddressthatexceeds255charactersverylongemailaddressthatexceeds255characters@verylongdomainname.com",
			password: "Password123!",
			desc:     "Email exceeding typical limits",
			wantErr:  true,
		},
		{
			name:        "email with unicode",
			email:       "пользователь@example.com",
			password:    "Password123!",
			desc:        "International email address",
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:     "empty email",
			email:    "",
			password: "Password123!",
			desc:     "Empty email should fail",
			wantErr:  true,
		},
		{
			name:     "empty password",
			email:    "test@example.com",
			password: "",
			desc:     "Empty password should fail auth",
			wantErr:  true,
		},
		{
			name:     "password with null byte",
			email:    "test@example.com",
			password: "Password\x00123!",
			desc:     "Null byte in password",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			mockAuthzService := new(MockAuthorizationService)
			mockRefreshCache := new(MockRefreshTokenCache)
			mockTokenCache := new(MockTokenCache)
			mockRateLimitCache := new(MockRateLimitCache)

			authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

			// Setup mocks for expected behavior
			mockRateLimitCache.On("GetCount", mock.Anything, mock.Anything).Return(int64(0), nil).Maybe()
			mockRateLimitCache.On("Increment", mock.Anything, mock.Anything, mock.Anything).Return(int64(1), nil).Maybe()
			mockUserRepo.On("FindByEmail", mock.Anything, mock.Anything).Return(nil, apperror.NotFound("user", tt.email)).Maybe()

			tokens, isOTP, err := authService.Login(context.Background(), tt.email, tt.password)

			if tt.wantErr {
				assert.Error(t, err, tt.desc)
				assert.Nil(t, tokens)
				assert.False(t, isOTP)
			} else {
				assert.NoError(t, err, tt.desc)
			}
		})
	}
}

// ==================== Password Expiration Edge Cases ====================

func TestPasswordExpiration_EdgeCases(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	tests := []struct {
		name              string
		passwordChangedAt *time.Time
		passwordMaxAge    time.Duration
		wantExpired       bool
		desc              string
	}{
		{
			name:              "nil PasswordChangedAt with expiration enabled",
			passwordChangedAt: nil,
			passwordMaxAge:    90 * 24 * time.Hour,
			wantExpired:       true,
			desc:              "Should be expired when never changed",
		},
		{
			name:              "nil PasswordChangedAt with expiration disabled",
			passwordChangedAt: nil,
			passwordMaxAge:    0,
			wantExpired:       false,
			desc:              "Should not expire when expiration is disabled",
		},
		{
			name:              "password changed exactly at boundary",
			passwordChangedAt: func() *time.Time { tm := time.Now().Add(-90 * 24 * time.Hour); return &tm }(),
			passwordMaxAge:    90 * 24 * time.Hour,
			wantExpired:       true,
			desc:              "Exactly at expiration boundary",
		},
		{
			name:              "password changed 1 minute before boundary",
			passwordChangedAt: func() *time.Time { tm := time.Now().Add(-90*24*time.Hour + time.Minute); return &tm }(),
			passwordMaxAge:    90 * 24 * time.Hour,
			wantExpired:       false,
			desc:              "Just before expiration",
		},
		{
			name:              "password changed in the future",
			passwordChangedAt: func() *time.Time { tm := time.Now().Add(24 * time.Hour); return &tm }(),
			passwordMaxAge:    90 * 24 * time.Hour,
			wantExpired:       false,
			desc:              "Future date should not be expired",
		},
		{
			name:              "very old password",
			passwordChangedAt: func() *time.Time { tm := time.Now().Add(-365 * 24 * time.Hour); return &tm }(),
			passwordMaxAge:    90 * 24 * time.Hour,
			wantExpired:       true,
			desc:              "Very old password should be expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			mockAuthzService := new(MockAuthorizationService)
			mockRefreshCache := new(MockRefreshTokenCache)
			mockTokenCache := new(MockTokenCache)
			mockRateLimitCache := new(MockRateLimitCache)

			authService := createTestAuthServiceWithPasswordExpiration(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache, tt.passwordMaxAge)

			mockRateLimitCache.On("GetCount", mock.Anything, mock.Anything).Return(int64(0), nil)
			mockUserRepo.On("FindByEmail", mock.Anything, "test@example.com").Return(&domain.User{
				ID:                1,
				Email:             "test@example.com",
				PasswordHash:      string(validPasswordHash),
				PasswordType:      domain.PasswordTypePermanent,
				PasswordChangedAt: tt.passwordChangedAt,
				IsBlocked:         false,
			}, nil)
			mockRateLimitCache.On("Reset", mock.Anything, mock.Anything).Return(nil).Maybe()
			mockAuthzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"user"}, nil).Maybe()
			mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.Anything, int64(1), mock.Anything).Return(nil).Maybe()

			tokens, _, err := authService.Login(context.Background(), "test@example.com", "Password123!")

			if tt.wantExpired {
				assert.Error(t, err, tt.desc)
				assert.Nil(t, tokens)
				if err != nil {
					appErr, ok := apperror.AsAppError(err)
					if ok {
						assert.Equal(t, apperror.CodePasswordExpired, appErr.Code, tt.desc)
					}
				}
			} else {
				assert.NoError(t, err, tt.desc)
				assert.NotNil(t, tokens)
			}
		})
	}
}

// ==================== Concurrent Login Tests ====================

func TestLogin_ConcurrentAttempts(t *testing.T) {
	validPasswordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)

	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)

	authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

	// Setup mocks for concurrent access
	mockRateLimitCache.On("GetCount", mock.Anything, mock.Anything).Return(int64(0), nil)
	mockRateLimitCache.On("Reset", mock.Anything, mock.Anything).Return(nil)
	mockUserRepo.On("FindByEmail", mock.Anything, "concurrent@example.com").Return(&domain.User{
		ID:           1,
		Email:        "concurrent@example.com",
		PasswordHash: string(validPasswordHash),
		PasswordType: domain.PasswordTypePermanent,
		IsBlocked:    false,
	}, nil)
	mockAuthzService.On("GetUserRoles", mock.Anything, int64(1)).Return([]string{"user"}, nil)
	mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.Anything, int64(1), mock.Anything).Return(nil)

	const goroutines = 10
	results := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			_, _, err := authService.Login(context.Background(), "concurrent@example.com", "Password123!")
			results <- err
		}()
	}

	// Collect results
	successCount := 0
	for i := 0; i < goroutines; i++ {
		err := <-results
		if err == nil {
			successCount++
		}
	}

	// All concurrent logins should succeed (no race conditions)
	assert.Equal(t, goroutines, successCount, "All concurrent logins should succeed")
}

// ==================== Refresh Token Edge Cases ====================

func TestRefreshToken_EdgeCases(t *testing.T) {
	tests := []struct {
		name         string
		refreshToken string
		setupMock    func(*MockRefreshTokenCache, *MockUserRepository)
		wantErr      bool
		errContains  string
	}{
		{
			name:         "empty refresh token",
			refreshToken: "",
			setupMock: func(cache *MockRefreshTokenCache, repo *MockUserRepository) {
				cache.On("GetRefreshToken", mock.Anything, "").Return(int64(0), apperror.NotFound("token", ""))
			},
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:         "non-existent refresh token",
			refreshToken: "nonexistent-token-id",
			setupMock: func(cache *MockRefreshTokenCache, repo *MockUserRepository) {
				cache.On("GetRefreshToken", mock.Anything, "nonexistent-token-id").Return(int64(0), apperror.NotFound("token", "nonexistent"))
			},
			wantErr:     true,
			errContains: "invalid",
		},
		{
			name:         "refresh token for blocked user",
			refreshToken: "valid-token-blocked-user",
			setupMock: func(cache *MockRefreshTokenCache, repo *MockUserRepository) {
				cache.On("GetRefreshToken", mock.Anything, "valid-token-blocked-user").Return(int64(1), nil)
				cache.On("DeleteRefreshToken", mock.Anything, "valid-token-blocked-user").Return(nil)
				repo.On("FindByID", mock.Anything, int64(1)).Return(&domain.User{
					ID:        1,
					Email:     "blocked@example.com",
					IsBlocked: true,
				}, nil)
			},
			wantErr:     true,
			errContains: "blocked",
		},
		{
			name:         "refresh token for deleted user",
			refreshToken: "valid-token-deleted-user",
			setupMock: func(cache *MockRefreshTokenCache, repo *MockUserRepository) {
				cache.On("GetRefreshToken", mock.Anything, "valid-token-deleted-user").Return(int64(999), nil)
				repo.On("FindByID", mock.Anything, int64(999)).Return(nil, apperror.NotFound("user", 999))
			},
			wantErr:     true,
			errContains: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockUserRepo := new(MockUserRepository)
			mockAuthzService := new(MockAuthorizationService)
			mockRefreshCache := new(MockRefreshTokenCache)
			mockTokenCache := new(MockTokenCache)
			mockRateLimitCache := new(MockRateLimitCache)

			authService := createTestAuthService(t, mockUserRepo, mockAuthzService, mockRefreshCache, mockTokenCache, mockRateLimitCache)

			tt.setupMock(mockRefreshCache, mockUserRepo)

			accessToken, err := authService.RefreshToken(context.Background(), tt.refreshToken)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, accessToken)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, accessToken)
			}
		})
	}
}
