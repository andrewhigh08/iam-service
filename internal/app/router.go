package app

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"

	// Registers the generated OpenAPI document that the Swagger UI serves.
	_ "github.com/andrewhigh08/iam-service/docs"
	"github.com/andrewhigh08/iam-service/internal/adapter/http/handler"
	"github.com/andrewhigh08/iam-service/internal/adapter/http/middleware"
	"github.com/andrewhigh08/iam-service/internal/domain"
)

// newRouter builds the gin engine in release mode with the global middleware chain and every
// route of the service.
func (a *App) newRouter(svcs *services) (*gin.Engine, error) {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	if err := r.SetTrustedProxies(a.cfg.Server.TrustedProxies); err != nil {
		return nil, fmt.Errorf("configure trusted proxies: %w", err)
	}
	if err := a.useMiddleware(r); err != nil {
		return nil, err
	}
	a.registerRoutes(r, svcs)
	return r, nil
}

// useMiddleware installs the global chain: request id, recovery, tracing, metrics, access
// log, security headers, CORS, body limit and the global rate limit, in that order.
func (a *App) useMiddleware(r *gin.Engine) error {
	r.Use(middleware.RequestID(), middleware.Recovery(a.base))
	if a.cfg.Telemetry.Enabled {
		r.Use(otelgin.Middleware(a.cfg.Telemetry.ServiceName))
	}
	r.Use(middleware.Metrics(), middleware.AccessLog(a.base), middleware.SecurityHeaders())
	cors, err := middleware.NewCORS(a.cfg.CORS.AllowedOrigins)
	if err != nil {
		return fmt.Errorf("configure CORS: %w", err)
	}
	if cors != nil {
		r.Use(cors)
	}
	r.Use(middleware.BodyLimit(middleware.DefaultBodyLimit), a.limiter.Middleware())
	return nil
}

// registerRoutes mounts the public, authentication and protected endpoints. Every endpoint
// that checks a password runs behind the login rate limit.
func (a *App) registerRoutes(r *gin.Engine, svcs *services) {
	authH := handler.NewAuthHandler(svcs.auth, svcs.authz, a.base)
	userH := handler.NewUserHandler(svcs.users, a.base)
	auditH := handler.NewAuditHandler(svcs.audit)
	healthH := handler.NewHealthHandler(a.db, a.rdb, a.version)
	jwksH := handler.NewJWKSHandler(svcs.auth)

	r.GET("/health/live", healthH.Live)
	r.GET("/health/ready", healthH.Ready)
	r.GET("/.well-known/jwks.json", jwksH.JWKS)
	handler.RegisterMetrics(r)
	handler.RegisterSwagger(r)

	auth := r.Group("/auth")
	auth.POST("/login", a.limiter.LoginMiddleware(), authH.Login)
	auth.POST("/refresh", authH.Refresh)
	auth.POST("/logout", authH.Logout)
	auth.POST("/change-password", a.limiter.LoginMiddleware(), authH.ChangeRequiredPassword)

	api := r.Group("/api/v1", authH.AuthMiddleware())
	api.POST("/change-password", a.limiter.LoginMiddleware(), authH.ChangePassword)
	api.POST("/logout-all", authH.LogoutAll)
	api.GET("/sessions", authH.ListSessions)
	api.DELETE("/sessions/:id", authH.RevokeSession)

	read := authH.RBACMiddleware(domain.ResourceUsers, domain.ActionRead)
	write := authH.RBACMiddleware(domain.ResourceUsers, domain.ActionWrite)
	auditRead := authH.RBACMiddleware(domain.ResourceAudit, domain.ActionRead)
	users := api.Group("/users")
	users.GET("", read, userH.ListUsers)
	users.GET("/:id", read, userH.GetUser)
	users.GET("/:id/audit", auditRead, auditH.ListUserAudit)
	users.POST("", write, userH.CreateUser)
	users.POST("/:id/block", write, userH.BlockUser)
	users.POST("/:id/unblock", write, userH.UnblockUser)
}
