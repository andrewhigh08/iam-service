package service

import (
	"io"
	"strconv"
	"strings"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Messages shared by several flows. The credential messages are deliberately uniform so that
// callers cannot tell accounts apart.
const (
	msgLoginRejected          = "invalid credentials"
	msgAccountBlocked         = "account is blocked"
	msgAccountLocked          = "account temporarily locked"
	msgLoginUnavailable       = "login is temporarily unavailable"
	msgRefreshRejected        = "invalid or expired refresh token"
	msgPasswordChangeRequired = "password change required"
	msgRevoked                = "token has been revoked"
	msgLoadUserFailed         = "failed to load user"
	msgLoadSessionFailed      = "failed to load session"
	msgDeleteSessionFailed    = "failed to delete session"
	msgListSessionsFailed     = "failed to list sessions"
	msgRevokeTokenFailed      = "failed to revoke access token"
	msgHashingFailed          = "failed to hash password"
	msgRecordAuditFailed      = "failed to record audit event"
	msgPolicyFailed           = "password does not meet the policy"
)

// normalizeEmail trims surrounding whitespace and lower-cases the address.
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// formatID renders a numeric identifier the way audit entries reference it.
func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}

// isNotFound reports whether err is an application error with code NOT_FOUND.
func isNotFound(err error) bool {
	appErr, ok := apperror.AsAppError(err)
	return ok && appErr.Code == apperror.CodeNotFound
}

// asInternal passes application errors through unchanged and wraps anything else as an
// internal error carrying msg. A nil err yields nil.
func asInternal(msg string, err error) error {
	if err == nil || apperror.IsAppError(err) {
		return err
	}
	return apperror.Internal(msg, err)
}

// invalidRoleError describes a role outside domain.ValidRoles.
func invalidRoleError() error {
	return apperror.ValidationError("invalid role", map[string]any{
		"errors": []string{"role must be one of: " + strings.Join(domain.ValidRoles(), ", ")},
	})
}

// componentLogger tags log with a component name, substituting a silent logger when log is nil.
func componentLogger(log *logger.Logger, component string) *logger.Logger {
	if log == nil {
		log = logger.New(logger.Config{Output: io.Discard})
	}
	return log.WithComponent(component)
}
