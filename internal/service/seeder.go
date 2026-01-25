// Package service contains the business logic layer of the application.
// Пакет service содержит слой бизнес-логики приложения.
package service

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Seeder handles database seeding operations for initial data setup.
// Seeder управляет операциями заполнения базы данных начальными данными.
//
// Used to create default RBAC policies and super admin user on first run.
// Используется для создания стандартных политик RBAC и супер-администратора при первом запуске.
type Seeder struct {
	db     *gorm.DB              // Database connection / Подключение к базе данных
	authz  *AuthorizationService // Authorization service for role management / Сервис авторизации для управления ролями
	logger *logger.Logger        // Logger instance / Экземпляр логгера
}

// NewSeeder creates a new Seeder instance.
// NewSeeder создаёт новый экземпляр Seeder.
func NewSeeder(db *gorm.DB, authz *AuthorizationService, log *logger.Logger) *Seeder {
	return &Seeder{
		db:     db,
		authz:  authz,
		logger: log.WithComponent("seeder"),
	}
}

// SeedAll runs all seeding operations in order.
// SeedAll запускает все операции заполнения по порядку.
//
// Order: 1) RBAC policies, 2) Super admin user.
// Порядок: 1) Политики RBAC, 2) Супер-администратор.
func (s *Seeder) SeedAll(ctx context.Context) error {
	s.logger.Info("starting database seeding")

	// Seed RBAC policies first / Сначала заполняем политики RBAC
	if err := s.SeedPolicies(ctx); err != nil {
		return err
	}

	// Then create super admin / Затем создаём супер-администратора
	if err := s.SeedSuperAdmin(ctx); err != nil {
		return err
	}

	s.logger.Info("database seeding completed successfully")
	return nil
}

// SeedPolicies seeds the base RBAC policies into Casbin.
// SeedPolicies заполняет базовые политики RBAC в Casbin.
//
// Policies define what actions each role can perform on resources:
// Политики определяют, какие действия каждая роль может выполнять над ресурсами:
//   - admin: full access to all resources / полный доступ ко всем ресурсам
//   - analyst: read-only users, full audit access / только чтение пользователей, полный доступ к аудиту
//   - viewer: minimal read-only access / минимальный доступ только на чтение
func (s *Seeder) SeedPolicies(_ context.Context) error {
	enforcer := s.authz.GetEnforcer()

	// Define base policies: role, resource, action
	// Определяем базовые политики: роль, ресурс, действие
	policies := [][]string{
		// Admin - full access / Админ - полный доступ
		{"role:admin", "users", "read"},
		{"role:admin", "users", "write"},
		{"role:admin", "users", "delete"},
		{"role:admin", "audit", "read"},
		{"role:admin", "settings", "read"},
		{"role:admin", "settings", "write"},

		// Analyst - read-only for users, full audit access
		// Аналитик - только чтение пользователей, полный доступ к аудиту
		{"role:analyst", "users", "read"},
		{"role:analyst", "audit", "read"},
		{"role:analyst", "settings", "read"},

		// Viewer - minimal access / Просмотрщик - минимальный доступ
		{"role:viewer", "users", "read"},
	}

	// Add policies that don't already exist
	// Добавляем политики, которые ещё не существуют
	for _, policy := range policies {
		hasPolicy, err := enforcer.HasPolicy(policy)
		if err != nil {
			s.logger.Error("failed to check policy", "policy", policy, "error", err)
			continue
		}
		if !hasPolicy {
			if _, err := enforcer.AddPolicy(policy); err != nil {
				s.logger.Error("failed to add policy", "policy", policy, "error", err)
			} else {
				s.logger.Debug("policy added", "policy", policy)
			}
		}
	}

	s.logger.Info("policies seeded successfully")
	return nil
}

// SeedSuperAdmin creates the default super admin user if it doesn't exist.
// SeedSuperAdmin создаёт супер-администратора по умолчанию, если он не существует.
//
// Uses hardcoded credentials for initial setup. Should be changed after first login.
// Использует захардкоженные учётные данные для начальной настройки. Следует изменить после первого входа.
func (s *Seeder) SeedSuperAdmin(ctx context.Context) error {
	// Default admin credentials / Учётные данные администратора по умолчанию
	const (
		adminEmail    = "samdawsonbai@gmail.com"
		adminPassword = "AdminSecret123!"
		adminFullName = "Super Admin"
	)

	// Check if admin already exists / Проверяем, существует ли админ
	var count int64
	if err := s.db.Model(&domain.User{}).Where("email = ?", adminEmail).Count(&count).Error; err != nil {
		s.logger.Error("failed to check for existing admin", "error", err)
		return err
	}

	if count > 0 {
		s.logger.Info("super admin already exists, skipping")
		return nil
	}

	// Hash password / Хэшируем пароль
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("failed to hash admin password", "error", err)
		return err
	}

	// Create admin user / Создаём пользователя-администратора
	admin := &domain.User{
		Email:        adminEmail,
		PasswordHash: string(hashedPassword),
		PasswordType: domain.PasswordTypePermanent,
		FullName:     adminFullName,
		IsBlocked:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := s.db.Create(admin).Error; err != nil {
		s.logger.Error("failed to create admin user", "error", err)
		return err
	}

	// Assign admin role / Назначаем роль администратора
	if err := s.authz.AddRoleToUser(ctx, admin.ID, "admin"); err != nil {
		s.logger.Error("failed to assign admin role", "error", err)
		// Clean up created user on role assignment failure
		// Удаляем созданного пользователя при ошибке назначения роли
		s.db.Unscoped().Delete(admin)
		return err
	}

	s.logger.Info("super admin created successfully", "email", adminEmail)
	return nil
}
