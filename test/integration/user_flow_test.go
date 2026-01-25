package integration

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

func TestIntegration_UserFlow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Setup test containers
	tc, err := SetupTestContainers(ctx)
	require.NoError(t, err)
	defer tc.Teardown(ctx)

	// Run migrations
	err = tc.RunMigrations()
	require.NoError(t, err)

	t.Run("create and retrieve user", func(t *testing.T) {
		// Clean up before test
		tc.CleanupData()

		// Create a user
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
		user := &domain.User{
			Email:        "test@example.com",
			PasswordHash: string(passwordHash),
			PasswordType: domain.PasswordTypePermanent,
			FullName:     "Test User",
			IsBlocked:    false,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		err := tc.DB.Create(user).Error
		require.NoError(t, err)
		assert.NotZero(t, user.ID)

		// Retrieve the user
		var retrieved domain.User
		err = tc.DB.Where("email = ?", "test@example.com").First(&retrieved).Error
		require.NoError(t, err)
		assert.Equal(t, user.Email, retrieved.Email)
		assert.Equal(t, user.FullName, retrieved.FullName)
	})

	t.Run("list users with pagination", func(t *testing.T) {
		// Clean up before test
		tc.CleanupData()

		// Create multiple users
		for i := 0; i < 25; i++ {
			passwordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
			user := &domain.User{
				Email:        "user" + string(rune('a'+i)) + "@example.com",
				PasswordHash: string(passwordHash),
				PasswordType: domain.PasswordTypePermanent,
				FullName:     "User " + string(rune('A'+i)),
				IsBlocked:    i%5 == 0, // Every 5th user is blocked
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			}
			err := tc.DB.Create(user).Error
			require.NoError(t, err)
		}

		// Test pagination - page 1
		var users []domain.User
		err := tc.DB.Where("deleted_at IS NULL").
			Order("created_at DESC").
			Limit(10).
			Offset(0).
			Find(&users).Error
		require.NoError(t, err)
		assert.Len(t, users, 10)

		// Test pagination - page 2
		err = tc.DB.Where("deleted_at IS NULL").
			Order("created_at DESC").
			Limit(10).
			Offset(10).
			Find(&users).Error
		require.NoError(t, err)
		assert.Len(t, users, 10)

		// Test filtering by status
		err = tc.DB.Where("deleted_at IS NULL AND is_blocked = ?", false).
			Find(&users).Error
		require.NoError(t, err)
		assert.Equal(t, 20, len(users)) // 25 - 5 blocked = 20 active
	})

	t.Run("block and unblock user", func(t *testing.T) {
		// Clean up before test
		tc.CleanupData()

		// Create a user
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
		user := &domain.User{
			Email:        "blocktest@example.com",
			PasswordHash: string(passwordHash),
			PasswordType: domain.PasswordTypePermanent,
			FullName:     "Block Test User",
			IsBlocked:    false,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		err := tc.DB.Create(user).Error
		require.NoError(t, err)

		// Block the user
		err = tc.DB.Model(&domain.User{}).
			Where("id = ?", user.ID).
			Update("is_blocked", true).Error
		require.NoError(t, err)

		// Verify user is blocked
		var blockedUser domain.User
		err = tc.DB.First(&blockedUser, user.ID).Error
		require.NoError(t, err)
		assert.True(t, blockedUser.IsBlocked)

		// Unblock the user
		err = tc.DB.Model(&domain.User{}).
			Where("id = ?", user.ID).
			Update("is_blocked", false).Error
		require.NoError(t, err)

		// Verify user is unblocked
		var unblockedUser domain.User
		err = tc.DB.First(&unblockedUser, user.ID).Error
		require.NoError(t, err)
		assert.False(t, unblockedUser.IsBlocked)
	})

	t.Run("audit logging", func(t *testing.T) {
		// Clean up before test
		tc.CleanupData()

		// Create a user
		passwordHash, _ := bcrypt.GenerateFromPassword([]byte("Password123!"), bcrypt.DefaultCost)
		user := &domain.User{
			Email:        "auditlog@example.com",
			PasswordHash: string(passwordHash),
			PasswordType: domain.PasswordTypePermanent,
			FullName:     "Audit Log Test User",
			IsBlocked:    false,
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}
		err := tc.DB.Create(user).Error
		require.NoError(t, err)

		// Create audit log entries
		for i := 0; i < 5; i++ {
			auditLog := &domain.AuditLog{
				UserID:       user.ID,
				Action:       "test.action",
				ResourceType: "user",
				ResourceID:   "1",
				Details:      []byte(`{"test": true}`),
				CreatedAt:    time.Now().Add(-time.Duration(i) * time.Minute),
			}
			err := tc.DB.Create(auditLog).Error
			require.NoError(t, err)
		}

		// Retrieve audit logs
		var logs []domain.AuditLog
		err = tc.DB.Where("user_id = ?", user.ID).
			Order("created_at DESC").
			Limit(10).
			Find(&logs).Error
		require.NoError(t, err)
		assert.Len(t, logs, 5)
	})
}

func TestIntegration_RedisCache(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Setup test containers
	tc, err := SetupTestContainers(ctx)
	require.NoError(t, err)
	defer tc.Teardown(ctx)

	t.Run("authorization cache", func(t *testing.T) {
		// Set a cached authorization decision
		key := "authz:decision:1:users:read"
		err := tc.Redis.Set(ctx, key, "1", 5*time.Minute).Err()
		require.NoError(t, err)

		// Retrieve the cached decision
		val, err := tc.Redis.Get(ctx, key).Result()
		require.NoError(t, err)
		assert.Equal(t, "1", val)

		// Delete the cached decision
		err = tc.Redis.Del(ctx, key).Err()
		require.NoError(t, err)

		// Verify deletion
		exists, err := tc.Redis.Exists(ctx, key).Result()
		require.NoError(t, err)
		assert.Equal(t, int64(0), exists)
	})

	t.Run("rate limiting cache", func(t *testing.T) {
		key := "ratelimit:login:192.168.1.1"

		// Increment counter
		for i := 0; i < 5; i++ {
			count, err := tc.Redis.Incr(ctx, key).Result()
			require.NoError(t, err)
			assert.Equal(t, int64(i+1), count)
		}

		// Set expiration
		err := tc.Redis.Expire(ctx, key, time.Minute).Err()
		require.NoError(t, err)

		// Verify count
		count, err := tc.Redis.Get(ctx, key).Int64()
		require.NoError(t, err)
		assert.Equal(t, int64(5), count)

		// Clean up
		tc.Redis.Del(ctx, key)
	})
}
