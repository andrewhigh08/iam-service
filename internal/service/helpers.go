package service

import (
	"io"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
)

// Messages shared by several flows. Every credential check answers msgLoginRejected so that
// callers cannot tell accounts apart; msgAccountBlocked is reserved for callers that already
// proved who they are.
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

// maxResourceIDBytes is the longest resource id the audit store accepts.
const maxResourceIDBytes = 255

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func hashPassword(pw string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", apperror.Internal(msgHashingFailed, err)
	}
	return string(hash), nil
}

// boundResourceID cuts id to maxResourceIDBytes without splitting a character. The HTTP
// layer bounds what it accepts; this is the backstop for every other caller.
func boundResourceID(id string) string {
	if len(id) <= maxResourceIDBytes {
		return id
	}
	cut := maxResourceIDBytes
	for cut > 0 && !utf8.RuneStart(id[cut]) {
		cut--
	}
	return id[:cut]
}

func formatID(id int64) string {
	return strconv.FormatInt(id, 10)
}

func isNotFound(err error) bool {
	appErr, ok := apperror.AsAppError(err)
	return ok && appErr.Code == apperror.CodeNotFound
}

func asInternal(msg string, err error) error {
	if err == nil || apperror.IsAppError(err) {
		return err
	}
	return apperror.Internal(msg, err)
}

func invalidRoleError() error {
	return apperror.ValidationError("invalid role", map[string]any{
		"errors": []string{"role must be one of: " + strings.Join(domain.ValidRoles(), ", ")},
	})
}

func componentLogger(log *logger.Logger, component string) *logger.Logger {
	if log == nil {
		log = logger.New(logger.Config{Output: io.Discard})
	}
	return log.WithComponent(component)
}
