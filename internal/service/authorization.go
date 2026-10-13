package service

import (
	"context"
	"errors"
	"strings"

	"github.com/casbin/casbin/v3"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/metrics"
)

// Prefixes that turn user ids and role names into casbin subjects.
const (
	subjectPrefix = "user:"
	rolePrefix    = "role:"
)

// AuthorizationService answers RBAC checks with a casbin enforcer. Subjects are "user:<id>"
// and roles are "role:<name>"; the enforcer owns policy storage and caching.
type AuthorizationService struct {
	enforcer casbin.IEnforcer
	logger   *logger.Logger
}

// NewAuthorizationService wraps enforcer, whose policies must already be loaded.
func NewAuthorizationService(enforcer casbin.IEnforcer, log *logger.Logger) (*AuthorizationService, error) {
	if enforcer == nil {
		return nil, errors.New("authorization service: enforcer is required")
	}
	return &AuthorizationService{
		enforcer: enforcer,
		logger:   componentLogger(log, "authz"),
	}, nil
}

// CheckAccess reports whether the user may perform action on resource and records the decision.
func (s *AuthorizationService) CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error) {
	allowed, err := s.enforcer.Enforce(subject(userID), resource, action)
	if err != nil {
		s.logger.FromContext(ctx).Error("authorization check failed",
			"user_id", userID, "resource", resource, "action", action, "error", err)
		return false, apperror.Internal("authorization check failed", err)
	}
	metrics.RecordAuthzDecision(allowed, resource, action)
	return allowed, nil
}

// AssignRole grants role to the user; granting a role twice is not an error.
func (s *AuthorizationService) AssignRole(ctx context.Context, userID int64, role string) error {
	if !domain.IsValidRole(role) {
		return invalidRoleError()
	}
	if _, err := s.enforcer.AddGroupingPolicy(subject(userID), roleName(role)); err != nil {
		return apperror.Internal("failed to assign role", err)
	}
	s.logger.FromContext(ctx).Info("role assigned", "user_id", userID, "role", role)
	return nil
}

// RolesOf returns the names of the roles granted to the user.
func (s *AuthorizationService) RolesOf(_ context.Context, userID int64) ([]string, error) {
	raw, err := s.enforcer.GetRolesForUser(subject(userID))
	if err != nil {
		return nil, apperror.Internal("failed to load roles", err)
	}
	roles := make([]string, 0, len(raw))
	for _, r := range raw {
		if name, ok := strings.CutPrefix(r, rolePrefix); ok {
			roles = append(roles, name)
		}
	}
	return roles, nil
}

// EnsurePolicies adds every policy the enforcer does not hold yet; it is safe to run repeatedly.
func (s *AuthorizationService) EnsurePolicies(ctx context.Context, policies []domain.Policy) error {
	for _, p := range policies {
		rule := []string{roleName(p.Role), p.Resource, p.Action}
		has, err := s.enforcer.HasPolicy(rule)
		if err != nil {
			return apperror.Internal("failed to check policy", err)
		}
		if has {
			continue
		}
		if _, err := s.enforcer.AddPolicy(rule); err != nil {
			return apperror.Internal("failed to add policy", err)
		}
		s.logger.FromContext(ctx).Info("policy added", "role", p.Role, "resource", p.Resource, "action", p.Action)
	}
	return nil
}

func subject(userID int64) string {
	return subjectPrefix + formatID(userID)
}

func roleName(role string) string {
	return rolePrefix + role
}
