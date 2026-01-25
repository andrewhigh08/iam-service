// Package service contains the business logic layer of the application.
// Пакет service содержит слой бизнес-логики приложения.
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
// Константа TTL кэша авторизации.
const (
	authzCacheTTL = 5 * time.Minute // 5 minutes / 5 минут
)

// AuthorizationService implements port.AuthorizationService with 3-level caching.
// AuthorizationService реализует интерфейс port.AuthorizationService с 3-уровневым кэшированием.
//
// Uses Casbin for RBAC with the following cache levels:
// Использует Casbin для RBAC со следующими уровнями кэша:
//   - L1: Casbin in-memory cache / Кэш Casbin в памяти
//   - L2: Redis external cache / Внешний кэш Redis
//   - L3: PostgreSQL (persistent) / PostgreSQL (постоянный)
type AuthorizationService struct {
	enforcer *casbin.Enforcer        // Casbin enforcer / Casbin enforcer
	cache    port.AuthorizationCache // Redis cache for decisions / Redis кэш для решений
	logger   *logger.Logger          // Logger instance / Экземпляр логгера
}

// NewAuthorizationService creates a new AuthorizationService instance.
// NewAuthorizationService создаёт новый экземпляр AuthorizationService.
func NewAuthorizationService(
	db *gorm.DB,
	cache port.AuthorizationCache,
	modelPath string,
	log *logger.Logger,
) (*AuthorizationService, error) {
	// Create GORM adapter for storing policies in PostgreSQL
	// Создаём GORM адаптер для хранения политик в PostgreSQL
	adapter, err := gormadapter.NewAdapterByDB(db)
	if err != nil {
		return nil, apperror.Internal("failed to create casbin adapter", err)
	}

	// Create enforcer with model and adapter
	// Создаём enforcer с моделью и адаптером
	enforcer, err := casbin.NewEnforcer(modelPath, adapter)
	if err != nil {
		return nil, apperror.Internal("failed to create casbin enforcer", err)
	}

	// Load policies from database / Загружаем политики из БД
	if err := enforcer.LoadPolicy(); err != nil {
		return nil, apperror.Internal("failed to load policies", err)
	}

	// Enable auto-save for policy changes / Включаем авто-сохранение изменений политик
	enforcer.EnableAutoSave(true)

	return &AuthorizationService{
		enforcer: enforcer,
		cache:    cache,
		logger:   log.WithComponent("authorization_service"),
	}, nil
}

// CheckAccess checks if a user has permission to perform an action on a resource.
// CheckAccess проверяет, имеет ли пользователь разрешение на выполнение действия над ресурсом.
//
// Uses 3-level caching: L1 (Casbin in-memory), L2 (Redis), L3 (PostgreSQL).
// Использует 3-уровневое кэширование: L1 (Casbin в памяти), L2 (Redis), L3 (PostgreSQL).
func (s *AuthorizationService) CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error) {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)

	// L2: Check Redis cache / L2: Проверяем Redis кэш
	if s.cache != nil {
		if allowed, found, err := s.cache.GetDecision(ctx, userID, resource, action); err == nil && found {
			log.LogAuthzDecision(userID, resource, action, allowed)
			return allowed, nil
		}
	}

	// L1+L3: Casbin checks through its in-memory cache + DB
	// L1+L3: Casbin проверяет через свой кэш в памяти + БД
	allowed, err := s.enforcer.Enforce(subject, resource, action)
	if err != nil {
		log.Error("casbin enforce failed", "user_id", userID, "resource", resource, "action", action, "error", err)
		return false, apperror.Internal("authorization check failed", err)
	}

	// Asynchronously cache the result in Redis
	// Асинхронно кэшируем результат в Redis
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
// AddRoleToUser назначает роль пользователю.
func (s *AuthorizationService) AddRoleToUser(ctx context.Context, userID int64, role string) error {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)
	roleStr := fmt.Sprintf("role:%s", role)

	// Add grouping policy: (g, user:123, role:admin)
	// Добавляем политику группировки: (g, user:123, role:admin)
	_, err := s.enforcer.AddGroupingPolicy(subject, roleStr)
	if err != nil {
		log.Error("failed to add role to user", "user_id", userID, "role", role, "error", err)
		return apperror.Internal("failed to add role", err)
	}

	// Invalidate user's cache / Инвалидируем кэш пользователя
	if s.cache != nil {
		if err := s.cache.InvalidateUser(ctx, userID); err != nil {
			log.Error("failed to invalidate user cache", "user_id", userID, "error", err)
		}
	}

	log.Info("role added to user", "user_id", userID, "role", role)
	return nil
}

// RemoveRoleFromUser removes a role from a user.
// RemoveRoleFromUser удаляет роль у пользователя.
func (s *AuthorizationService) RemoveRoleFromUser(ctx context.Context, userID int64, role string) error {
	log := s.logger.WithContext(ctx)
	subject := fmt.Sprintf("user:%d", userID)
	roleStr := fmt.Sprintf("role:%s", role)

	_, err := s.enforcer.RemoveGroupingPolicy(subject, roleStr)
	if err != nil {
		log.Error("failed to remove role from user", "user_id", userID, "role", role, "error", err)
		return apperror.Internal("failed to remove role", err)
	}

	// Invalidate user's cache / Инвалидируем кэш пользователя
	if s.cache != nil {
		if err := s.cache.InvalidateUser(ctx, userID); err != nil {
			log.Error("failed to invalidate user cache", "user_id", userID, "error", err)
		}
	}

	log.Info("role removed from user", "user_id", userID, "role", role)
	return nil
}

// GetUserRoles retrieves all roles assigned to a user.
// GetUserRoles получает все роли, назначенные пользователю.
func (s *AuthorizationService) GetUserRoles(_ context.Context, userID int64) ([]string, error) {
	subject := fmt.Sprintf("user:%d", userID)

	// Casbin stores roles in format "role:admin"
	// Casbin хранит роли в формате "role:admin"
	roles, err := s.enforcer.GetRolesForUser(subject)
	if err != nil {
		s.logger.Error("failed to get roles for user", "user_id", userID, "error", err)
		return nil, apperror.Internal("failed to get user roles", err)
	}

	// Remove "role:" prefix / Удаляем префикс "role:"
	cleanRoles := make([]string, 0, len(roles))
	for _, role := range roles {
		if strings.HasPrefix(role, "role:") {
			cleanRoles = append(cleanRoles, strings.TrimPrefix(role, "role:"))
		}
	}

	return cleanRoles, nil
}

// ReloadPolicies reloads RBAC policies from the database.
// ReloadPolicies перезагружает политики RBAC из базы данных.
// Call this after policy changes.
// Вызывайте после изменения политик.
func (s *AuthorizationService) ReloadPolicies(ctx context.Context) error {
	if err := s.enforcer.LoadPolicy(); err != nil {
		s.logger.Error("failed to reload policies", "error", err)
		return apperror.Internal("failed to reload policies", err)
	}

	// Invalidate all cached decisions / Инвалидируем все закэшированные решения
	if s.cache != nil {
		if err := s.cache.InvalidateAll(ctx); err != nil {
			s.logger.Error("failed to invalidate all cache", "error", err)
		}
	}

	s.logger.Info("policies reloaded successfully")
	return nil
}

// GetEnforcer returns the underlying Casbin enforcer.
// GetEnforcer возвращает базовый Casbin enforcer.
// Used by seeder for initial policy setup.
// Используется seeder'ом для начальной настройки политик.
func (s *AuthorizationService) GetEnforcer() *casbin.Enforcer {
	return s.enforcer
}
