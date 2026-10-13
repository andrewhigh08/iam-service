// Package service contains the business logic layer of the application.
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
//
// Used to create default RBAC policies and super admin user on first run.
type Seeder struct {
	db     *gorm.DB              // Database connection
	authz  *AuthorizationService // Authorization service for role management
	logger *logger.Logger        // Logger instance
}

// NewSeeder creates a new Seeder instance.
func NewSeeder(db *gorm.DB, authz *AuthorizationService, log *logger.Logger) *Seeder {
	return &Seeder{
		db:     db,
		authz:  authz,
		logger: log.WithComponent("seeder"),
	}
}

// SeedAll runs all seeding operations in order.
//
// Order: 1) RBAC policies, 2) Super admin user.
func (s *Seeder) SeedAll(ctx context.Context) error {
	s.logger.Info("starting database seeding")

	// Seed RBAC policies first
	if err := s.SeedPolicies(ctx); err != nil {
		return err
	}

	// Then create super admin
	if err := s.SeedSuperAdmin(ctx); err != nil {
		return err
	}

	s.logger.Info("database seeding completed successfully")
	return nil
}

// SeedPolicies seeds the base RBAC policies into Casbin.
//
// Policies define what actions each role can perform on resources:
//   - admin: full access to all resources
//   - analyst: read-only users, full audit access
//   - viewer: minimal read-only access
func (s *Seeder) SeedPolicies(_ context.Context) error {
	enforcer := s.authz.GetEnforcer()

	// Define base policies: role, resource, action
	policies := [][]string{
		// Admin - full access
		{"role:admin", "users", "read"},
		{"role:admin", "users", "write"},
		{"role:admin", "users", "delete"},
		{"role:admin", "audit", "read"},
		{"role:admin", "settings", "read"},
		{"role:admin", "settings", "write"},

		// Analyst - read-only for users, full audit access
		{"role:analyst", "users", "read"},
		{"role:analyst", "audit", "read"},
		{"role:analyst", "settings", "read"},

		// Viewer - minimal access
		{"role:viewer", "users", "read"},
	}

	// Add policies that don't already exist
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
//
// Uses hardcoded credentials for initial setup. Should be changed after first login.
func (s *Seeder) SeedSuperAdmin(ctx context.Context) error {
	// Default admin credentials
	const (
		adminEmail    = "samdawsonbai@gmail.com"
		adminPassword = "AdminSecret123!"
		adminFullName = "Super Admin"
	)

	// Check if admin already exists
	var count int64
	if err := s.db.Model(&domain.User{}).Where("email = ?", adminEmail).Count(&count).Error; err != nil {
		s.logger.Error("failed to check for existing admin", "error", err)
		return err
	}

	if count > 0 {
		s.logger.Info("super admin already exists, skipping")
		return nil
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		s.logger.Error("failed to hash admin password", "error", err)
		return err
	}

	// Create admin user
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

	// Assign admin role
	if err := s.authz.AddRoleToUser(ctx, admin.ID, "admin"); err != nil {
		s.logger.Error("failed to assign admin role", "error", err)
		// Clean up created user on role assignment failure
		s.db.Unscoped().Delete(admin)
		return err
	}

	s.logger.Info("super admin created successfully", "email", adminEmail)
	return nil
}
