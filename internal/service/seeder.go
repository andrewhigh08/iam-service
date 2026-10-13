package service

import (
	"context"
	"errors"
	"slices"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// adminFullName is the display name of the seeded administrator.
const adminFullName = "Administrator"

// PolicyAuthorizer is the authorization service as the Seeder needs it: role assignment plus
// idempotent policy installation. *AuthorizationService satisfies it.
type PolicyAuthorizer interface {
	port.AuthorizationService
	EnsurePolicies(ctx context.Context, policies []domain.Policy) error
}

// Seeder installs the default policies and the initial administrator. Logger may be nil.
type Seeder struct {
	Users  port.UserRepository
	Authz  PolicyAuthorizer
	Logger *logger.Logger
}

// Seed ensures the default policies exist, creates the administrator when adminEmail is set
// and no user with that email exists, and grants the admin role to an existing account that
// lacks it. It is idempotent; the caller provides the transaction and the advisory lock that
// serialize concurrent replicas.
func (s *Seeder) Seed(ctx context.Context, adminEmail, adminPassword string) error {
	if s.Users == nil || s.Authz == nil {
		return errors.New("seeder: user repository and authorization service are required")
	}
	log := componentLogger(s.Logger, "seeder").FromContext(ctx)
	if err := s.Authz.EnsurePolicies(ctx, domain.DefaultPolicies()); err != nil {
		return err
	}
	email := normalizeEmail(adminEmail)
	if email == "" {
		log.Info("admin seeding skipped: no admin email configured")
		return nil
	}
	if adminPassword == "" {
		return apperror.Internal("admin password is required to seed the administrator", nil)
	}
	admin, err := s.Users.FindByEmail(ctx, email)
	switch {
	case isNotFound(err):
		return s.createAdmin(ctx, email, adminPassword, log)
	case err != nil:
		return asInternal("failed to check admin account", err)
	}
	return s.ensureAdminRole(ctx, admin, log)
}

// createAdmin inserts the administrator and grants the admin role. The caller's transaction
// is rolled back on failure, so no half-created account survives.
func (s *Seeder) createAdmin(ctx context.Context, email, password string, log *logger.Logger) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return apperror.Internal(msgHashingFailed, err)
	}
	now := time.Now()
	admin := &domain.User{
		Email:             email,
		PasswordHash:      string(hash),
		PasswordTemporary: false,
		PasswordChangedAt: now,
		FullName:          adminFullName,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := s.Users.Create(ctx, admin); err != nil {
		return asInternal("failed to create admin account", err)
	}
	if err := s.Authz.AssignRole(ctx, admin.ID, domain.RoleAdmin); err != nil {
		return err
	}
	log.Info("admin account created", "user_id", admin.ID, "email", email)
	return nil
}

// ensureAdminRole grants the admin role to an existing account configured as the
// administrator, so that repointing ADMIN_EMAIL or restoring the policy table separately
// from the users never leaves the service without an administrator.
func (s *Seeder) ensureAdminRole(ctx context.Context, admin *domain.User, log *logger.Logger) error {
	roles, err := s.Authz.RolesOf(ctx, admin.ID)
	if err != nil {
		return err
	}
	if slices.Contains(roles, domain.RoleAdmin) {
		log.Debug("admin account already exists", "user_id", admin.ID)
		return nil
	}
	if err := s.Authz.AssignRole(ctx, admin.ID, domain.RoleAdmin); err != nil {
		return err
	}
	log.Info("admin role granted to the existing admin account", "user_id", admin.ID, "email", admin.Email)
	return nil
}
