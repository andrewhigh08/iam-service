package port

import (
	"context"

	"github.com/golang-jwt/jwt/v5"

	"github.com/andrewhigh08/iam-service/internal/domain"
)

// TokenPair is an issued access/refresh token pair; ExpiresIn is the access token TTL in seconds.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
}

// Claims is the payload of an access token.
type Claims struct {
	UserID    int64    `json:"uid"`
	Email     string   `json:"email"`
	Roles     []string `json:"roles"`
	SessionID string   `json:"sid"`
	jwt.RegisteredClaims
}

// Values of LoginResult.Reason when a password change is required.
const (
	ReasonTemporaryPassword = "temporary_password"
	ReasonPasswordExpired   = "password_expired"
)

// LoginResult is the outcome of a successful credential check. Tokens, User and Roles are set
// together; Tokens is nil when the user must change the password before receiving tokens.
type LoginResult struct {
	Tokens                *TokenPair
	User                  *domain.User
	Roles                 []string
	RequirePasswordChange bool
	Reason                string
}

// CreateUserInput carries the data needed to create a user.
// Temporary marks the initial password as one that must be changed at the first login.
type CreateUserInput struct {
	Email     string
	Password  string
	FullName  string
	Role      string
	Temporary bool
}

// AuthService authenticates users and manages their tokens and sessions.
type AuthService interface {
	// Login checks the credentials and either issues tokens or asks for a password change.
	Login(ctx context.Context, email, password string, meta domain.ClientMeta) (*LoginResult, error)
	// Refresh rotates the refresh token and issues a new pair.
	Refresh(ctx context.Context, refreshToken string, meta domain.ClientMeta) (*TokenPair, error)
	// Logout ends the session of refreshToken and revokes accessToken when one is given.
	Logout(ctx context.Context, refreshToken, accessToken string, meta domain.ClientMeta) error
	// LogoutAll ends every session of the user and revokes all access tokens issued before now.
	LogoutAll(ctx context.Context, userID int64, meta domain.ClientMeta) error
	// ValidateAccessToken verifies signature, expiry, issuer, algorithm, jti blacklist and the
	// user revocation instant. Returns apperror.ServiceUnavailable when the revocation store is down.
	ValidateAccessToken(ctx context.Context, token string) (*Claims, error)
	// ChangePassword replaces the password of an authenticated user, revokes every session and
	// returns a fresh pair for the caller. Wrong current passwords count towards the lockout.
	ChangePassword(ctx context.Context, userID int64, oldPassword, newPassword string, meta domain.ClientMeta) (*TokenPair, error)
	// ChangeRequiredPassword replaces a temporary or expired password without authentication.
	ChangeRequiredPassword(ctx context.Context, email, oldPassword, newPassword string, meta domain.ClientMeta) (*TokenPair, error)
	// ListSessions returns the live sessions of the user, marking the one whose sid is currentSID.
	ListSessions(ctx context.Context, userID int64, currentSID string) ([]domain.Session, error)
	// RevokeSession ends the session of the user identified by sid and blacklists its access token.
	RevokeSession(ctx context.Context, userID int64, sid string, meta domain.ClientMeta) error
	// PublicJWKS returns the RFC 7517 JSON Web Key Set for the signing key.
	PublicJWKS() ([]byte, error)
}

// UserService manages user accounts.
type UserService interface {
	Create(ctx context.Context, in CreateUserInput, actor domain.Actor) (*domain.User, error)
	GetByID(ctx context.Context, id int64) (*domain.User, error)
	List(ctx context.Context, f UserFilter) ([]domain.User, int64, error)
	// Block disables the account and revokes its sessions and tokens. Blocking an already
	// blocked user repeats the revocation and succeeds.
	Block(ctx context.Context, id int64, actor domain.Actor) error
	Unblock(ctx context.Context, id int64, actor domain.Actor) error
}

// AuthorizationService answers role-based access checks.
type AuthorizationService interface {
	CheckAccess(ctx context.Context, userID int64, resource, action string) (bool, error)
	AssignRole(ctx context.Context, userID int64, role string) error
	RolesOf(ctx context.Context, userID int64) ([]string, error)
}

// AuditService records and reads audit events.
type AuditService interface {
	// Record stores e, joining the transaction carried in ctx when there is one.
	Record(ctx context.Context, e domain.AuditEvent) error
	// ListByActor returns up to limit of the most recent entries recorded for actions of the
	// user actorID, newest first. A non-positive limit means the default page size.
	ListByActor(ctx context.Context, actorID int64, limit int) ([]domain.AuditLog, error)
}
