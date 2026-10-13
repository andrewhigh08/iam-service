// Package service contains the business logic layer of the application.
package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/casbin/casbin/v2"
	gormadapter "github.com/casbin/gorm-adapter/v3"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// Authorization cache TTL constant.
const (
	authzCacheTTL = 5 * time.Minute // 5 minutes
)

// AuthorizationService implements port.AuthorizationService with 3-level caching.
//
// Uses Casbin for RBAC with the following cache levels:
//   - L1: Casbin in-memory cache
//   - L2: Redis external cache
//   - L3: PostgreSQL (persistent)
type AuthorizationService struct {
	enforcer *casbin.Enforcer        // Casbin enforcer / Casbin enforcer
	cache    port.AuthorizationCache // Redis cache for decisions
	logger   *logger.Logger          // Logger instance
}

// NewAuthorizationService creates a new AuthorizationService instance.
func NewAuthorizationService(
	db *gorm.DB,
	cache port.AuthorizationCache,
	modelPath string,
	log *logger.Logger,
) (*AuthorizationService, error) {
	// Create GORM adapter for storing policies in PostgreSQL
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, apperror.Internal("failed to create casbin adapter", err)
	}

	// Create enforcer with model and adapter
	enforcer, err := casbin.NewEnforcer(modelPath, adapter)
	if err != nil {
		return nil, apperror.Internal("failed to create casbin enforcer", err)
	}

	// Load policies from database
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, apperror.Internal("failed to load policies", err)
	}

	// Enable auto-save for policy changes
	enforcer.EnableAutoSave(true)

	return &AuthorizationService{
		enforcer: enforcer,
		cache:    cache,
		logger:   log.WithComponent("authorization_service"),
	}, nil
}

// CheckAccess checks if a user has permission to perform an action on a resource.
//
// Uses 3-level caching: L1 (Casbin in-memory), L2 (Redis), L3 (PostgreSQL).
func (s *AuthorizationService) CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error) {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)

	// L2: Check Redis cache
	if s.cache != nil {
		if allowed, found, err := s.cache.GetDecision(ctx, userID, resource, action); err == nil && found {
			log.LogAuthzDecision(userID, resource, action, allowed)
			return allowed, nil
		}
	}

	// L1+L3: Casbin checks through its in-memory cache + DB
	allowed, err := s.enforcer.Enforce(subject, resource, action)
	if err != nil {
		log.Error("casbin enforce failed", "user_id", userID, "resource", resource, "action", action, "error", err)
		return false, apperror.Internal("authorization check failed", err)
	}

	// Asynchronously cache the result in Redis
	if s.cache != nil {
		go func() {
			if cacheErr := s.cache.SetDecision(context.Background(), userID, resource, action, allowed, authzCacheTTL); cacheErr != nil {
				log.Error("failed to cache authz decision", "error", cacheErr)
			}
		}()
	}

	log.LogAuthzDecision(userID, resource, action, allowed)
	return allowed, nil
}

// AddRoleToUser assigns a role to a user.
func (s *AuthorizationService) AddRoleToUser(ctx context.Context, userID int64, role string) error {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)
	roleStr := fmt.Sprintf("role:%s", role)

	// Add grouping policy: (g, user:123, role:admin)
	_, err := s.enforcer.AddGroupingPolicy(subject, roleStr)
	if err != nil {
		log.Error("failed to add role to user", "user_id", userID, "role", role, "error", err)
		return apperror.Internal("failed to add role", err)
	}

	// Invalidate user's cache
	if s.cache != nil {
		if err := s.cache.InvalidateUser(ctx, userID); err != nil {
			log.Error("failed to invalidate user cache", "user_id", userID, "error", err)
		}
	}

	log.Info("role added to user", "user_id", userID, "role", role)
	return nil
}

// RemoveRoleFromUser removes a role from a user.
func (s *AuthorizationService) RemoveRoleFromUser(ctx context.Context, userID int64, role string) error {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)
	roleStr := fmt.Sprintf("role:%s", role)

	_, err := s.enforcer.RemoveGroupingPolicy(subject, roleStr)
	if err != nil {
		log.Error("failed to remove role from user", "user_id", userID, "role", role, "error", err)
		return apperror.Internal("failed to remove role", err)
	}

	// Invalidate user's cache
	if s.cache != nil {
		if err := s.cache.InvalidateUser(ctx, userID); err != nil {
			log.Error("failed to invalidate user cache", "user_id", userID, "error", err)
		}
	}

	log.Info("role removed from user", "user_id", userID, "role", role)
	return nil
}

// GetUserRoles retrieves all roles assigned to a user.
func (s *AuthorizationService) GetUserRoles(_ context.Context, userID int64) ([]string, error) {
	subject := fmt.Sprintf("user:%d", userID)

	// Casbin stores roles in format "role:admin"
	roles, err := s.enforcer.GetRolesForUser(subject)
	if err != nil {
		s.logger.Error("failed to get roles for user", "user_id", userID, "error", err)
		return nil, apperror.Internal("failed to get user roles", err)
	}

	// Remove "role:" prefix
	cleanRoles := make([]string, 0, len(roles))
	for _, role := range roles {
		if strings.HasPrefix(role, "role:") {
			cleanRoles = append(cleanRoles, strings.TrimPrefix(role, "role:"))
		}
	}

	return cleanRoles, nil
}

// ReloadPolicies reloads RBAC policies from the database.
// Call this after policy changes.
func (s *AuthorizationService) ReloadPolicies(ctx context.Context) error {
	if err := s.enforcer.LoadPolicy(); err != nil {
		s.logger.Error("failed to reload policies", "error", err)
		return apperror.Internal("failed to reload policies", err)
	}

	// Invalidate all cached decisions
	if s.cache != nil {
		if err := s.cache.InvalidateAll(ctx); err != nil {
			s.logger.Error("failed to invalidate all cache", "error", err)
		}
	}

	s.logger.Info("policies reloaded successfully")
	return nil
}

// GetEnforcer returns the underlying Casbin enforcer.
// Used by seeder for initial policy setup.
func (s *AuthorizationService) GetEnforcer() *casbin.Enforcer {
	return s.enforcer
}
