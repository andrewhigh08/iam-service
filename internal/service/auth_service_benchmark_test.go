package service_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
	"github.com/andrewhigh08/iam-service/internal/service"
)

// ==================== JWT Benchmarks ====================

// BenchmarkGenerateAccessToken measures JWT RS256 token generation performance.
// Target: ~1000 ops/sec (RS256 is computationally expensive).
func BenchmarkGenerateAccessToken(b *testing.B) {
	authService := createBenchmarkAuthService(b)
	ctx := context.Background()

	userID := int64(1)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		tokens, err := authService.GenerateTokenForUser(ctx, userID)
		if err != nil {
			b.Fatalf("failed to generate token: %v", err)
		}
		_ = tokens
	}
}

// BenchmarkValidateToken measures JWT parsing and signature verification performance.
// Target: ~5000 ops/sec (validation is faster than signing).
func BenchmarkValidateToken(b *testing.B) {
	authService := createBenchmarkAuthService(b)
	ctx := context.Background()

	// Generate a valid token first
	tokens, err := authService.GenerateTokenForUser(ctx, 1)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		claims, err := authService.ValidateToken(ctx, tokens.AccessToken)
		if err != nil {
			b.Fatalf("failed to validate token: %v", err)
		}
		_ = claims
	}
}

// BenchmarkValidateToken_Parallel measures concurrent token validation.
func BenchmarkValidateToken_Parallel(b *testing.B) {
	authService := createBenchmarkAuthService(b)
	ctx := context.Background()

	// Generate a valid token first
	tokens, err := authService.GenerateTokenForUser(ctx, 1)
	require.NoError(b, err)

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			claims, err := authService.ValidateToken(ctx, tokens.AccessToken)
			if err != nil {
				b.Fatalf("failed to validate token: %v", err)
			}
			_ = claims
		}
	})
}

// ==================== Bcrypt Benchmarks ====================

// BenchmarkBcryptHash measures password hashing performance.
// Target: ~10 ops/sec with default cost (this is intentionally slow for security).
func BenchmarkBcryptHash(b *testing.B) {
	password := []byte("SecurePassword123!")

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
		if err != nil {
			b.Fatalf("failed to hash password: %v", err)
		}
		_ = hash
	}
}

// BenchmarkBcryptCompare measures password verification performance.
// Target: ~10 ops/sec (same as hashing).
func BenchmarkBcryptCompare(b *testing.B) {
	password := []byte("SecurePassword123!")
	hash, _ := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := bcrypt.CompareHashAndPassword(hash, password)
		if err != nil {
			b.Fatalf("password mismatch: %v", err)
		}
	}
}

// BenchmarkBcryptHash_VariousCosts compares different bcrypt cost factors.
func BenchmarkBcryptHash_VariousCosts(b *testing.B) {
	password := []byte("SecurePassword123!")

	costs := []int{4, 6, 8, 10, 12}
	for _, cost := range costs {
		b.Run(costName(cost), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hash, err := bcrypt.GenerateFromPassword(password, cost)
				if err != nil {
					b.Fatalf("failed to hash password: %v", err)
				}
				_ = hash
			}
		})
	}
}

func costName(cost int) string {
	return "cost_" + string(rune('0'+cost/10)) + string(rune('0'+cost%10))
}

// ==================== JTI Generation Benchmark ====================

// BenchmarkGenerateJTI measures unique token ID generation.
// Target: ~100000 ops/sec (crypto/rand based).
func BenchmarkGenerateJTI(b *testing.B) {
	bytes := make([]byte, 16)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := rand.Read(bytes)
		if err != nil {
			b.Fatalf("failed to generate JTI: %v", err)
		}
	}
}

// ==================== RSA Key Operations Benchmarks ====================

// BenchmarkRSAKeyGeneration measures RSA 2048-bit key pair generation.
func BenchmarkRSAKeyGeneration(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			b.Fatalf("failed to generate RSA key: %v", err)
		}
		_ = key
	}
}

// BenchmarkRSASign measures RS256 signing performance directly.
func BenchmarkRSASign(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := jwt.MapClaims{
		"user_id": 1,
		"email":   "test@example.com",
		"roles":   []string{"admin"},
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err := token.SignedString(privateKey)
		if err != nil {
			b.Fatalf("failed to sign token: %v", err)
		}
		_ = signed
	}
}

// BenchmarkRSAVerify measures RS256 signature verification performance.
func BenchmarkRSAVerify(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	claims := jwt.MapClaims{
		"user_id": 1,
		"email":   "test@example.com",
		"roles":   []string{"admin"},
		"exp":     time.Now().Add(15 * time.Minute).Unix(),
		"iat":     time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signed, _ := token.SignedString(privateKey)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, err := jwt.Parse(signed, func(token *jwt.Token) (interface{}, error) {
			return publicKey, nil
		})
		if err != nil {
			b.Fatalf("failed to verify token: %v", err)
		}
	}
}

// ==================== Token Size Benchmarks ====================

// BenchmarkValidateToken_VariousRoleCounts measures validation with different role counts.
func BenchmarkValidateToken_VariousRoleCounts(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	publicKey := &privateKey.PublicKey

	roleCounts := []int{1, 5, 10, 50, 100}

	for _, count := range roleCounts {
		b.Run(roleCountName(count), func(b *testing.B) {
			roles := generateRoles(count)
			claims := port.Claims{
				UserID: 1,
				Email:  "test@example.com",
				Roles:  roles,
				RegisteredClaims: jwt.RegisteredClaims{
					ID:        "test-jti",
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
				},
			}

			token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
			signed, _ := token.SignedString(privateKey)

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				_, err := jwt.ParseWithClaims(signed, &port.Claims{}, func(token *jwt.Token) (interface{}, error) {
					return publicKey, nil
				})
				if err != nil {
					b.Fatalf("failed to validate token: %v", err)
				}
			}
		})
	}
}

func roleCountName(count int) string {
	return "roles_" + itoa(count)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var result []byte
	for n > 0 {
		result = append([]byte{byte('0' + n%10)}, result...)
		n /= 10
	}
	return string(result)
}

func generateRoles(count int) []string {
	roles := make([]string, count)
	for i := 0; i < count; i++ {
		roles[i] = "role_" + itoa(i)
	}
	return roles
}

// ==================== Memory Allocation Benchmarks ====================

// BenchmarkTokenGeneration_MemoryProfile focuses on memory allocations.
func BenchmarkTokenGeneration_MemoryProfile(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := port.Claims{
		UserID: 1,
		Email:  "test@example.com",
		Roles:  []string{"admin", "user"},
		RegisteredClaims: jwt.RegisteredClaims{
			ID:        "test-jti-12345678901234567890",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(15 * time.Minute)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Issuer:    "iam-service",
		},
	}

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signed, err := token.SignedString(privateKey)
		if err != nil {
			b.Fatalf("failed to sign token: %v", err)
		}
		_ = signed
	}
}

// ==================== Password Length Benchmarks ====================

// BenchmarkBcryptHash_PasswordLength measures impact of password length on hashing.
// Note: bcrypt rejects passwords > 72 bytes in modern Go versions.
func BenchmarkBcryptHash_PasswordLength(b *testing.B) {
	// Only test valid password lengths (max 72 bytes for bcrypt)
	lengths := []int{8, 16, 32, 64, 72}

	for _, length := range lengths {
		b.Run("len_"+itoa(length), func(b *testing.B) {
			password := []byte(strings.Repeat("a", length))

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
				if err != nil {
					b.Fatalf("failed to hash password: %v", err)
				}
				_ = hash
			}
		})
	}
}

// ==================== Helper Functions ====================

func createBenchmarkAuthService(b *testing.B) *service.AuthService {
	b.Helper()

	tempDir := b.TempDir()
	privateKeyPath := filepath.Join(tempDir, "keys", "private.pem")
	publicKeyPath := filepath.Join(tempDir, "keys", "public.pem")

	// Generate and save keys
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(b, err)

	err = os.MkdirAll(filepath.Dir(privateKeyPath), 0o750)
	require.NoError(b, err)

	// Save private key
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	require.NoError(b, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile(privateKeyPath, privateKeyPEM, 0o600)
	require.NoError(b, err)

	// Save public key
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(b, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile(publicKeyPath, publicKeyPEM, 0o644)
	require.NoError(b, err)

	// Create mocks
	mockUserRepo := new(MockUserRepository)
	mockAuthzService := new(MockAuthorizationService)
	mockRefreshCache := new(MockRefreshTokenCache)
	mockTokenCache := new(MockTokenCache)
	mockRateLimitCache := new(MockRateLimitCache)
	mockAuditService := new(MockAuditService)

	// Setup mock expectations for GenerateTokenForUser
	mockUserRepo.On("FindByID", mock.Anything, mock.AnythingOfType("int64")).Return(&domain.User{
		ID:           1,
		Email:        "bench@example.com",
		PasswordType: domain.PasswordTypePermanent,
	}, nil).Maybe()
	mockAuthzService.On("GetUserRoles", mock.Anything, mock.AnythingOfType("int64")).Return([]string{"admin", "user"}, nil).Maybe()
	mockRefreshCache.On("StoreRefreshToken", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()
	mockAuditService.On("LogAction", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil).Maybe()

	log := logger.New(logger.Config{Level: "error", Format: "json"})

	config := service.AuthServiceConfig{
		PrivateKeyPath:   privateKeyPath,
		PublicKeyPath:    publicKeyPath,
		TokenTTL:         15 * time.Minute,
		RefreshTTL:       7 * 24 * time.Hour,
		MaxLoginAttempts: 5,
		LockoutDuration:  15 * time.Minute,
		DevMode:          false,
	}

	authService, err := service.NewAuthService(
		mockUserRepo,
		mockAuthzService,
		mockAuditService,
		mockRefreshCache,
		mockTokenCache,
		mockRateLimitCache,
		config,
		log,
	)
	require.NoError(b, err)

	return authService
}
