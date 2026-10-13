package service

import (
	"context"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/andrewhigh08/iam-service/internal/domain"
	"github.com/andrewhigh08/iam-service/internal/pkg/apperror"
	"github.com/andrewhigh08/iam-service/internal/pkg/validator"
	"github.com/andrewhigh08/iam-service/internal/port"
)

// ChangePassword verifies oldPassword, stores newPassword, revokes every session and access
// token of the user and returns a fresh pair for the caller. A wrong old password counts
// towards the account lockout exactly like a failed login.
func (s *AuthService) ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string, meta domain.ClientMeta) (*port.TokenPair, error) {
	user, err := s.deps.Users.FindByID(ctx, userID)
	if err != nil {
		return nil, asInternal(msgLoadUserFailed, err)
	}
	if user.IsBlocked {
		return nil, apperror.Unauthorized(msgAccountBlocked)
	}
	if err := s.checkLock(ctx, user.Email, user.ID, meta); err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(oldPassword)) != nil {
		if rejectErr := s.rejectCredentials(ctx, user.Email, user.ID, "invalid_old_password", meta); rejectErr != nil {
			return nil, rejectErr
		}
		return nil, apperror.Unauthorized("invalid old password")
	}
	s.resetAttempts(ctx, user.Email)
	return s.replacePassword(ctx, user, newPassword, meta, map[string]any{"forced": false})
}

// ChangeRequiredPassword replaces a temporary or expired password for a user who cannot log
// in yet. The credentials are verified exactly like a login, so failures count towards the
// lockout, and whether a change is required is checked only after the old password passed.
func (s *AuthService) ChangeRequiredPassword(ctx context.Context, email, oldPassword, newPassword string, meta domain.ClientMeta) (*port.TokenPair, error) {
	user, err := s.authenticate(ctx, normalizeEmail(email), oldPassword, meta)
	if err != nil {
		return nil, err
	}
	reason := s.passwordChangeReason(user)
	if reason == "" {
		return nil, apperror.BadRequest("password change not required")
	}
	return s.replacePassword(ctx, user, newPassword, meta, map[string]any{"forced": true, "reason": reason})
}

// replacePassword validates and stores newPassword, revokes the user's sessions and access
// tokens, issues a fresh pair and audits the change with details.
func (s *AuthService) replacePassword(ctx context.Context, user *domain.User, newPassword string, meta domain.ClientMeta, details map[string]any) (*port.TokenPair, error) {
	if err := validator.ValidatePassword(newPassword, s.cfg.PasswordPolicy); err != nil {
		return nil, err
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(newPassword)) == nil {
		return nil, apperror.ValidationError(msgPolicyFailed, map[string]any{
			"errors": []string{"new password must differ from the current one"},
		})
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return nil, err
	}
	now := s.now()
	if err = s.deps.Users.UpdatePassword(ctx, user.ID, hash, false, now); err != nil {
		return nil, asInternal("failed to update password", err)
	}
	user.PasswordHash = hash
	user.PasswordTemporary = false
	user.PasswordChangedAt = now
	removed, err := s.revoker.revokeAll(ctx, user.ID, now)
	if err != nil {
		return nil, err
	}
	issued, err := s.issueTokens(ctx, user, meta, time.Time{})
	if err != nil {
		return nil, err
	}
	details["sessions_revoked"] = removed
	details["sid"] = issued.sid
	s.audit(ctx, user.ID, domain.AuditActionPasswordChange, formatID(user.ID), meta, details)
	s.logger.FromContext(ctx).Info("password changed", "user_id", user.ID)
	return issued.tokens, nil
}
