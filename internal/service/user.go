package service

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// UserDeps lists the collaborators and settings of UserService. Logger may be nil and a zero
// PasswordPolicy means validator.DefaultPolicy.
type UserDeps struct {
	Users          port.UserRepository
	Tx             port.TxManager
	Authz          port.AuthorizationService
	Audit          port.AuditService
	Sessions       port.SessionStore
	Revocations    port.RevocationStore
	Logger         *logger.Logger
	AccessTTL      time.Duration
	PasswordPolicy validator.Policy
}

// UserService implements port.UserService.
type UserService struct {
	deps    UserDeps
	revoker accessRevoker
	logger  *logger.Logger
	now     func() time.Time
}

// NewUserService validates deps and returns a UserService.
func NewUserService(deps UserDeps) (*UserService, error) {
	if err := validateUserDeps(deps); err != nil {
		return nil, err
	}
	if deps.PasswordPolicy == (validator.Policy{}) {
		deps.PasswordPolicy = validator.DefaultPolicy()
	}
	return &UserService{
		deps: deps,
		revoker: accessRevoker{
			sessions:    deps.Sessions,
			revocations: deps.Revocations,
			accessTTL:   deps.AccessTTL,
		},
		logger: componentLogger(deps.Logger, "user"),
		now:    time.Now,
	}, nil
}

func validateUserDeps(deps UserDeps) error {
	var missing string
	switch {
	case deps.Users == nil:
		missing = "user repository"
	case deps.Tx == nil:
		missing = "transaction manager"
	case deps.Authz == nil:
		missing = "authorization service"
	case deps.Audit == nil:
		missing = "audit service"
	case deps.Sessions == nil:
		missing = "session store"
	case deps.Revocations == nil:
		missing = "revocation store"
	case deps.AccessTTL <= 0:
		return errors.New("user service: access TTL must be positive")
	default:
		return nil
	}
	return errors.New("user service: " + missing + " is required")
}

// Create registers a user with the given role. The initial password may be marked temporary
// so that it must be changed at the first login.
func (s *UserService) Create(ctx context.Context, in port.CreateUserInput, actor domain.Actor) (*domain.User, error) {
	if !domain.IsValidRole(in.Role) {
		return nil, invalidRoleError()
	}
	email := normalizeEmail(in.Email)
	if email == "" {
		return nil, apperror.ValidationError("invalid email", map[string]any{"errors": []string{"email is required"}})
	}
	if err := validator.ValidatePassword(in.Password, s.deps.PasswordPolicy); err != nil {
		return nil, err
	}
	exists, err := s.deps.Users.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, asInternal("failed to check email", err)
	}
	if exists {
		return nil, apperror.Conflict("user", "email", email)
	}
	hash, err := hashPassword(in.Password)
	if err != nil {
		return nil, err
	}
	now := s.now()
	user := &domain.User{
		Email:             email,
		PasswordHash:      hash,
		PasswordTemporary: in.Temporary,
		PasswordChangedAt: now,
		FullName:          strings.TrimSpace(in.FullName),
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err = s.deps.Users.Create(ctx, user); err != nil {
		return nil, asInternal("failed to create user", err)
	}
	if err = s.deps.Authz.AssignRole(ctx, user.ID, in.Role); err != nil {
		return nil, s.compensateCreate(ctx, user.ID, err)
	}
	s.recordAudit(ctx, actor, domain.AuditActionUserCreate, user.ID, map[string]any{
		"email":     email,
		"full_name": user.FullName,
		"role":      in.Role,
		"temporary": in.Temporary,
	})
	s.logger.FromContext(ctx).Info("user created", "user_id", user.ID, "role", in.Role)
	return user, nil
}

// compensateCreate removes a user whose role could not be assigned and reports the failure.
func (s *UserService) compensateCreate(ctx context.Context, userID int64, cause error) error {
	log := s.logger.FromContext(ctx)
	log.Error("failed to assign role, removing user", "user_id", userID, "error", cause)
	if err := s.deps.Users.HardDelete(ctx, userID); err != nil {
		log.Error("failed to remove user after role assignment failure", "user_id", userID, "error", err)
		return apperror.Internal("failed to assign role and to remove the user", errors.Join(cause, err))
	}
	return apperror.Internal("failed to assign role", cause)
}

// recordAudit writes an audit entry outside any transaction; a failure is logged, not surfaced.
func (s *UserService) recordAudit(ctx context.Context, actor domain.Actor, action string, userID int64, details map[string]any) {
	if err := s.deps.Audit.Record(ctx, auditEvent(actor, action, userID, details)); err != nil {
		s.logger.FromContext(ctx).Error(msgRecordAuditFailed, "action", action, "error", err)
	}
}

func auditEvent(actor domain.Actor, action string, userID int64, details map[string]any) domain.AuditEvent {
	return domain.AuditEvent{
		ActorID:      actor.UserID,
		Action:       action,
		ResourceType: domain.AuditResourceTypeUser,
		ResourceID:   formatID(userID),
		Details:      details,
		ClientMeta:   actor.ClientMeta,
	}
}

// GetByID returns the user with the given id.
func (s *UserService) GetByID(ctx context.Context, id int64) (*domain.User, error) {
	user, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return nil, asInternal(msgLoadUserFailed, err)
	}
	return user, nil
}

// List returns one page of users matching f and the total number of matches.
func (s *UserService) List(ctx context.Context, f port.UserFilter) ([]domain.User, int64, error) {
	users, total, err := s.deps.Users.List(ctx, f)
	if err != nil {
		return nil, 0, asInternal("failed to list users", err)
	}
	return users, total, nil
}

// Block disables the account and audits it in one transaction, then ends the user's sessions
// and invalidates the access tokens issued so far. Blocking an already blocked user repeats
// only the revocation, so a block whose revocation failed can be retried.
func (s *UserService) Block(ctx context.Context, id int64, actor domain.Actor) error {
	user, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return asInternal(msgLoadUserFailed, err)
	}
	log := s.logger.FromContext(ctx)
	if user.IsBlocked {
		log.Info("user already blocked, repeating the revocation", "user_id", id, "actor_id", actor.UserID)
	} else if blockErr := s.setBlocked(ctx, user, true, actor, domain.AuditActionUserBlock); blockErr != nil {
		return blockErr
	}
	removed, err := s.revoker.revokeAll(ctx, id, s.now())
	if err != nil {
		log.Error("user blocked but session revocation failed", "user_id", id, "error", err)
		return err
	}
	log.Info("user blocked", "user_id", id, "actor_id", actor.UserID, "sessions_revoked", removed)
	return nil
}

// Unblock re-enables the account and audits it in one transaction.
func (s *UserService) Unblock(ctx context.Context, id int64, actor domain.Actor) error {
	user, err := s.deps.Users.FindByID(ctx, id)
	if err != nil {
		return asInternal(msgLoadUserFailed, err)
	}
	if !user.IsBlocked {
		return apperror.BadRequest("user is not blocked")
	}
	err = s.setBlocked(ctx, user, false, actor, domain.AuditActionUserUnblock)
	if err != nil {
		return err
	}
	s.logger.FromContext(ctx).Info("user unblocked", "user_id", id, "actor_id", actor.UserID)
	return nil
}

// setBlocked persists the blocked flag of user together with the audit entry for action in
// a single transaction.
func (s *UserService) setBlocked(ctx context.Context, user *domain.User, blocked bool, actor domain.Actor, action string) error {
	err := s.deps.Tx.WithinTx(ctx, func(txCtx context.Context) error {
		if err := s.deps.Users.SetBlocked(txCtx, user.ID, blocked); err != nil {
			return err
		}
		return s.deps.Audit.Record(txCtx, auditEvent(actor, action, user.ID, map[string]any{"email": user.Email}))
	})
	if err != nil {
		return asInternal("failed to update user", err)
	}
	user.IsBlocked = blocked
	return nil
}
