package app

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"io/fs"

	"github.com/casbin/casbin/v3"

	"github.com/andrewhigh08/iam-service/internal/adapter/pgrepo"
	"github.com/andrewhigh08/iam-service/internal/adapter/redisstore"
	"github.com/andrewhigh08/iam-service/internal/port"
	"github.com/andrewhigh08/iam-service/internal/service"
)

// seedLockKey is the PostgreSQL advisory lock that serializes seeding across replicas.
const seedLockKey int64 = 42

// services groups what the router and the seeder need from the service layer.
type services struct {
	auth     port.AuthService
	users    port.UserService
	authz    port.AuthorizationService
	audit    port.AuditService
	tx       *pgrepo.TxManager
	enforcer casbin.IEnforcer
	seeder   *service.Seeder
}

func (a *App) newServices(enforcer casbin.IEnforcer) (*services, error) {
	privateKey, publicKey, err := a.loadKeys()
	if err != nil {
		return nil, err
	}

	userRepo := pgrepo.NewUserRepository(a.db)
	auditRepo := pgrepo.NewAuditLogRepository(a.db)
	txManager := pgrepo.NewTxManager(a.db)
	sessions := redisstore.NewSessionStore(a.rdb)
	revocations := redisstore.NewRevocationStore(a.rdb)
	attempts := redisstore.NewLoginAttemptStore(a.rdb)

	audit, err := service.NewAuditService(auditRepo, a.base)
	if err != nil {
		return nil, err
	}
	authz, err := service.NewAuthorizationService(enforcer, a.base)
	if err != nil {
		return nil, err
	}
	users, err := service.NewUserService(service.UserDeps{
		Users:       userRepo,
		Tx:          txManager,
		Authz:       authz,
		Audit:       audit,
		Sessions:    sessions,
		Revocations: revocations,
		Logger:      a.base,
		AccessTTL:   a.cfg.JWT.AccessTokenTTL,
	})
	if err != nil {
		return nil, err
	}
	auth, err := service.NewAuthService(service.AuthDeps{
		Users:       userRepo,
		Authz:       authz,
		Audit:       audit,
		Sessions:    sessions,
		Revocations: revocations,
		Attempts:    attempts,
		Logger:      a.base,
	}, service.AuthConfig{
		PrivateKey:       privateKey,
		PublicKey:        publicKey,
		Issuer:           a.cfg.JWT.Issuer,
		AccessTTL:        a.cfg.JWT.AccessTokenTTL,
		RefreshTTL:       a.cfg.JWT.RefreshTokenTTL,
		SessionMaxAge:    a.cfg.JWT.SessionMaxAge,
		MaxLoginAttempts: a.cfg.Lockout.MaxAttempts,
		LockoutDuration:  a.cfg.Lockout.Duration,
		PasswordMaxAge:   a.cfg.Password.MaxAge,
	})
	if err != nil {
		return nil, err
	}
	seeder, err := service.NewSeeder(userRepo, authz, a.base)
	if err != nil {
		return nil, err
	}

	return &services{
		auth:     auth,
		users:    users,
		authz:    authz,
		audit:    audit,
		tx:       txManager,
		enforcer: enforcer,
		seeder:   seeder,
	}, nil
}

// loadKeys reads the RSA signing key pair. In DEV_MODE a missing pair is generated in place.
func (a *App) loadKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privPath, pubPath := a.cfg.JWT.PrivateKeyPath, a.cfg.JWT.PublicKeyPath
	privateKey, publicKey, err := service.LoadRSAKeyPair(privPath, pubPath)
	switch {
	case err == nil:
		return privateKey, publicKey, nil
	case !errors.Is(err, fs.ErrNotExist):
		return nil, nil, fmt.Errorf("load signing keys: %w", err)
	case !a.cfg.DevMode:
		return nil, nil, fmt.Errorf("load signing keys: %w (DEV_MODE=true generates a pair)", err)
	}

	a.log.Warn("signing keys not found, generating a new pair", "private_key", privPath, "public_key", pubPath)
	privateKey, publicKey, err = service.GenerateRSAKeyPair(privPath, pubPath)
	if err != nil {
		return nil, nil, fmt.Errorf("generate signing keys: %w", err)
	}
	return privateKey, publicKey, nil
}

// seed installs the default policies and the administrator inside one transaction that holds
// a transaction-scoped advisory lock, so replicas starting together seed exactly once. The
// DEV_MODE password fallback was already applied when the configuration was loaded.
func (a *App) seed(ctx context.Context, svcs *services) error {
	err := svcs.tx.WithinLockedTx(ctx, seedLockKey, func(ctx context.Context) error {
		// A replica that held the lock first may have added policies this one has not seen.
		if err := svcs.enforcer.LoadPolicy(); err != nil {
			return fmt.Errorf("reload policies: %w", err)
		}
		return svcs.seeder.Seed(ctx, a.cfg.Admin.Email, a.cfg.Admin.Password)
	})
	if err != nil {
		return fmt.Errorf("seed database: %w", err)
	}
	return nil
}
