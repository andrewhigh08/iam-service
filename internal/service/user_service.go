// Package service contains the business logic layer of the application.
package service

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	"github.com/andrewhigh08/iam-service/internal/adapter/repository/postgres"
	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// UserService implements port.UserService interface.
//
// Handles user management operations including CRUD, blocking,
// and audit logging using saga pattern for distributed transactions.
type UserService struct {
	userRepo  port.UserRepository          // User repository
	txManager *postgres.TransactionManager // Transaction manager
	authz     port.AuthorizationService    // Authorization service
	audit     port.AuditService            // Audit service
	logger    *logger.Logger               // Logger instance
}

// NewUserService creates a new UserService instance.
func NewUserService(
	userRepo port.UserRepository,
	txManager *postgres.TransactionManager,
	authz port.AuthorizationService,
	audit port.AuditService,
	log *logger.Logger,
) *UserService {
	return &UserService{
		userRepo:  userRepo,
		txManager: txManager,
		authz:     authz,
		audit:     audit,
		logger:    log.WithComponent("user_service"),
	}
}

// CreateUser creates a new user with the specified role.
//
// Uses saga pattern: creates user in transaction, then assigns role.
// If role assignment fails, executes compensating transaction (hard delete).
func (s *UserService) CreateUser(ctx context.Context, req *domain.CreateUserRequest, createdBy int64, ipAddress, userAgent string) (*domain.User, error) {
	log := s.logger.WithContext(ctx)

	// Set default password type
	if req.PasswordType == "" {
		req.PasswordType = domain.PasswordTypePermanent
	}

	// Check if email already exists
	exists, err := s.userRepo.ExistsByEmail(ctx, req.Email)
	if err != nil {
		log.Error("failed to check email existence", "error", err)
		return nil, err
	}
	if exists {
		return nil, apperror.Conflict("user", "email", req.Email)
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Error("failed to hash password", "error", err)
		return nil, apperror.Internal("failed to hash password", err)
	}

	// Create user object
	user := &domain.User{
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		PasswordType: req.PasswordType,
		FullName:     req.FullName,
		IsBlocked:    false,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	// Create user in transaction with audit log
	var createdUser *domain.User
	err = s.txManager.WithTransaction(ctx, func(tx *gorm.DB) error {
		// Create user
		repo, ok := s.userRepo.(*postgres.UserRepository)
		if !ok {
			return apperror.Internal("invalid repository type", nil)
		}
		if createErr := repo.CreateTx(ctx, tx, user); createErr != nil {
			return createErr
		}
		createdUser = user

		// Audit log within transaction
		return s.audit.LogActionWithContextTx(ctx, tx, createdBy, "user.create", "user", fmt.Sprintf("%d", user.ID), map[string]any{
			"email":         user.Email,
			"full_name":     user.FullName,
			"role":          req.Role,
			"password_type": req.PasswordType,
		}, ipAddress, userAgent)
	})

	if err != nil {
		log.Error("failed to create user in transaction", "error", err)
		return nil, err
	}

	// Assign role AFTER successful commit (saga pattern)
	if err := s.authz.AddRoleToUser(ctx, createdUser.ID, req.Role); err != nil {
		log.Error("failed to assign role, executing compensating transaction", "user_id", createdUser.ID, "error", err)

		// Compensating action: hard delete user
		if repo, ok := s.userRepo.(*postgres.UserRepository); ok {
			if deleteErr := repo.HardDelete(ctx, createdUser.ID); deleteErr != nil {
				log.Error("CRITICAL: failed to cleanup user after role assignment failure", "user_id", createdUser.ID, "error", deleteErr)
				return nil, apperror.Internal("user created but setup failed (cleanup also failed)", err)
			}
		}

		return nil, apperror.Internal("failed to assign role, user creation rolled back", err)
	}

	log.Info("user created successfully", "user_id", createdUser.ID, "email", createdUser.Email)
	return createdUser, nil
}

// GetUserByID retrieves a user by their unique identifier.
func (s *UserService) GetUserByID(ctx context.Context, id int64) (*domain.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

// ListUsers retrieves users with filtering and pagination.
func (s *UserService) ListUsers(ctx context.Context, filter port.UserFilter) ([]domain.User, int64, error) {
	return s.userRepo.List(ctx, filter)
}

// BlockUser blocks a user account, preventing login.
func (s *UserService) BlockUser(ctx context.Context, id, blockedBy int64, ipAddress, userAgent string) error {
	log := s.logger.WithContext(ctx)

	// Get user first
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if user.IsBlocked {
		return apperror.BadRequest("user is already blocked")
	}

	// Block user in transaction with audit log
	err = s.txManager.WithTransaction(ctx, func(tx *gorm.DB) error {
		user.IsBlocked = true
		user.UpdatedAt = time.Now()

		repo, ok := s.userRepo.(*postgres.UserRepository)
		if !ok {
			return apperror.Internal("invalid repository type", nil)
		}
		if updateErr := repo.UpdateTx(ctx, tx, user); updateErr != nil {
			return updateErr
		}

		return s.audit.LogActionWithContextTx(ctx, tx, blockedBy, "user.block", "user", fmt.Sprintf("%d", id), map[string]any{
			"target_user_id": id,
		}, ipAddress, userAgent)
	})

	if err != nil {
		log.Error("failed to block user", "user_id", id, "error", err)
		return err
	}

	log.Info("user blocked successfully", "user_id", id, "blocked_by", blockedBy)
	return nil
}

// UnblockUser unblocks a previously blocked user account.
func (s *UserService) UnblockUser(ctx context.Context, id, unblockedBy int64, ipAddress, userAgent string) error {
	log := s.logger.WithContext(ctx)

	// Get user first
	user, err := s.userRepo.FindByID(ctx, id)
	if err != nil {
		return err
	}

	if !user.IsBlocked {
		return apperror.BadRequest("user is not blocked")
	}

	// Unblock user in transaction with audit log
	err = s.txManager.WithTransaction(ctx, func(tx *gorm.DB) error {
		user.IsBlocked = false
		user.UpdatedAt = time.Now()

		repo, ok := s.userRepo.(*postgres.UserRepository)
		if !ok {
			return apperror.Internal("invalid repository type", nil)
		}
		if updateErr := repo.UpdateTx(ctx, tx, user); updateErr != nil {
			return updateErr
		}

		return s.audit.LogActionWithContextTx(ctx, tx, unblockedBy, "user.unblock", "user", fmt.Sprintf("%d", id), map[string]any{
			"target_user_id": id,
		}, ipAddress, userAgent)
	})

	if err != nil {
		log.Error("failed to unblock user", "user_id", id, "error", err)
		return err
	}

	log.Info("user unblocked successfully", "user_id", id, "unblocked_by", unblockedBy)
	return nil
}
