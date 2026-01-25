package service_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/mock"
)

// ==================== Authorization Benchmarks ====================

// BenchmarkCheckAccess_CacheHit measures performance with cache hit.
// Target: ~50000 ops/sec (in-memory/Redis lookup).
func BenchmarkCheckAccess_CacheHit(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		allowed, found, err := mockCache.GetDecision(ctx, 1, "users", "read")
		if err != nil || !found {
			b.Fatalf("cache lookup failed")
		}
		_ = allowed
	}
}

// BenchmarkCheckAccess_CacheMiss measures performance with cache miss.
// This would trigger Casbin enforcer lookup in real implementation.
func BenchmarkCheckAccess_CacheMiss(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(false, false, nil)
	mockCache.On("SetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		_, found, err := mockCache.GetDecision(ctx, 1, "users", "read")
		if err != nil {
			b.Fatalf("cache lookup failed")
		}
		if !found {
			// Simulate cache set after enforcer lookup
			_ = mockCache.SetDecision(ctx, 1, "users", "read", true, 5*time.Minute)
		}
	}
}

// BenchmarkCheckAccess_Parallel measures concurrent access checking.
func BenchmarkCheckAccess_Parallel(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			allowed, found, err := mockCache.GetDecision(ctx, 1, "users", "read")
			if err != nil || !found {
				b.Fatalf("cache lookup failed")
			}
			_ = allowed
		}
	})
}

// BenchmarkSetDecision measures cache write performance.
func BenchmarkSetDecision(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("SetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := mockCache.SetDecision(ctx, 1, "users", "read", true, 5*time.Minute)
		if err != nil {
			b.Fatalf("cache set failed")
		}
	}
}

// BenchmarkInvalidateUser measures user cache invalidation performance.
func BenchmarkInvalidateUser(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("InvalidateUser", mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := mockCache.InvalidateUser(ctx, int64(i%1000))
		if err != nil {
			b.Fatalf("cache invalidation failed")
		}
	}
}

// BenchmarkInvalidateAll measures global cache invalidation performance.
func BenchmarkInvalidateAll(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("InvalidateAll", mock.Anything).Return(nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := mockCache.InvalidateAll(ctx)
		if err != nil {
			b.Fatalf("cache invalidation failed")
		}
	}
}

// ==================== Role Operations Benchmarks ====================

// BenchmarkGetUserRoles measures role retrieval performance.
func BenchmarkGetUserRoles(b *testing.B) {
	mockAuthzService := new(MockAuthorizationService)
	mockAuthzService.On("GetUserRoles", mock.Anything, mock.Anything).Return([]string{"admin", "user", "viewer"}, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		roles, err := mockAuthzService.GetUserRoles(ctx, 1)
		if err != nil {
			b.Fatalf("failed to get roles: %v", err)
		}
		_ = roles
	}
}

// BenchmarkAddRoleToUser measures role assignment performance.
func BenchmarkAddRoleToUser(b *testing.B) {
	mockAuthzService := new(MockAuthorizationService)
	mockAuthzService.On("AddRoleToUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()
	roles := []string{"admin", "user", "viewer", "manager", "operator"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		role := roles[i%len(roles)]
		err := mockAuthzService.AddRoleToUser(ctx, int64(i%1000), role)
		if err != nil {
			b.Fatalf("failed to add role: %v", err)
		}
	}
}

// BenchmarkRemoveRoleFromUser measures role removal performance.
func BenchmarkRemoveRoleFromUser(b *testing.B) {
	mockAuthzService := new(MockAuthorizationService)
	mockAuthzService.On("RemoveRoleFromUser", mock.Anything, mock.Anything, mock.Anything).Return(nil)

	ctx := context.Background()
	roles := []string{"admin", "user", "viewer", "manager", "operator"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		role := roles[i%len(roles)]
		err := mockAuthzService.RemoveRoleFromUser(ctx, int64(i%1000), role)
		if err != nil {
			b.Fatalf("failed to remove role: %v", err)
		}
	}
}

// ==================== Policy Benchmarks ====================

// BenchmarkReloadPolicies measures policy reload performance.
func BenchmarkReloadPolicies(b *testing.B) {
	mockAuthzService := new(MockAuthorizationService)
	mockAuthzService.On("ReloadPolicies", mock.Anything).Return(nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		err := mockAuthzService.ReloadPolicies(ctx)
		if err != nil {
			b.Fatalf("failed to reload policies: %v", err)
		}
	}
}

// ==================== Varied User Count Benchmarks ====================

// BenchmarkCheckAccess_VariedUserCount measures scalability with different user counts.
func BenchmarkCheckAccess_VariedUserCount(b *testing.B) {
	userCounts := []int{1, 10, 100, 1000, 10000}

	for _, count := range userCounts {
		b.Run(fmt.Sprintf("users_%d", count), func(b *testing.B) {
			mockCache := new(MockAuthorizationCache)
			mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)

			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				userID := int64(i % count)
				allowed, found, err := mockCache.GetDecision(ctx, userID, "users", "read")
				if err != nil || !found {
					b.Fatalf("cache lookup failed")
				}
				_ = allowed
			}
		})
	}
}

// ==================== Resource Variety Benchmarks ====================

// BenchmarkCheckAccess_VariedResources measures performance with different resources.
func BenchmarkCheckAccess_VariedResources(b *testing.B) {
	resources := []string{"users", "roles", "permissions", "audit", "settings", "api:v1:users", "api:v1:roles"}

	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resource := resources[i%len(resources)]
		allowed, found, err := mockCache.GetDecision(ctx, 1, resource, "read")
		if err != nil || !found {
			b.Fatalf("cache lookup failed")
		}
		_ = allowed
	}
}

// BenchmarkCheckAccess_VariedActions measures performance with different actions.
func BenchmarkCheckAccess_VariedActions(b *testing.B) {
	actions := []string{"read", "write", "delete", "create", "update", "manage", "admin"}

	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		action := actions[i%len(actions)]
		allowed, found, err := mockCache.GetDecision(ctx, 1, "users", action)
		if err != nil || !found {
			b.Fatalf("cache lookup failed")
		}
		_ = allowed
	}
}

// ==================== Cache TTL Benchmarks ====================

// BenchmarkSetDecision_VariedTTL measures cache set with different TTLs.
func BenchmarkSetDecision_VariedTTL(b *testing.B) {
	ttls := []time.Duration{
		1 * time.Second,
		30 * time.Second,
		1 * time.Minute,
		5 * time.Minute,
		15 * time.Minute,
		1 * time.Hour,
	}

	for _, ttl := range ttls {
		b.Run(fmt.Sprintf("ttl_%s", ttl), func(b *testing.B) {
			mockCache := new(MockAuthorizationCache)
			mockCache.On("SetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)

			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				err := mockCache.SetDecision(ctx, 1, "users", "read", true, ttl)
				if err != nil {
					b.Fatalf("cache set failed")
				}
			}
		})
	}
}

// ==================== Role Count Benchmarks ====================

// BenchmarkGetUserRoles_VariedRoleCount measures role retrieval with different role counts.
func BenchmarkGetUserRoles_VariedRoleCount(b *testing.B) {
	roleCounts := []int{1, 3, 5, 10, 20, 50}

	for _, count := range roleCounts {
		b.Run(fmt.Sprintf("roles_%d", count), func(b *testing.B) {
			roles := make([]string, count)
			for i := 0; i < count; i++ {
				roles[i] = fmt.Sprintf("role_%d", i)
			}

			mockAuthzService := new(MockAuthorizationService)
			mockAuthzService.On("GetUserRoles", mock.Anything, mock.Anything).Return(roles, nil)

			ctx := context.Background()

			b.ResetTimer()
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				result, err := mockAuthzService.GetUserRoles(ctx, 1)
				if err != nil {
					b.Fatalf("failed to get roles: %v", err)
				}
				_ = result
			}
		})
	}
}

// ==================== Mixed Workload Benchmarks ====================

// BenchmarkMixedWorkload simulates realistic mixed authorization workload.
func BenchmarkMixedWorkload(b *testing.B) {
	mockCache := new(MockAuthorizationCache)
	mockCache.On("GetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(true, true, nil)
	mockCache.On("SetDecision", mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(nil)
	mockCache.On("InvalidateUser", mock.Anything, mock.Anything).Return(nil)

	mockAuthzService := new(MockAuthorizationService)
	mockAuthzService.On("GetUserRoles", mock.Anything, mock.Anything).Return([]string{"admin", "user"}, nil)

	ctx := context.Background()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		op := i % 100

		switch {
		case op < 70: // 70% reads (CheckAccess)
			_, _, _ = mockCache.GetDecision(ctx, int64(i%1000), "users", "read")
		case op < 85: // 15% role lookups
			_, _ = mockAuthzService.GetUserRoles(ctx, int64(i%1000))
		case op < 95: // 10% cache writes
			_ = mockCache.SetDecision(ctx, int64(i%1000), "users", "read", true, 5*time.Minute)
		default: // 5% invalidations
			_ = mockCache.InvalidateUser(ctx, int64(i%1000))
		}
	}
}
