// Package main is the entry point for the IAM Service API server.
// Пакет main является точкой входа для API сервера IAM Service.
//
// The IAM Service provides authentication, authorization, and user management
// capabilities using JWT tokens and Casbin RBAC.
// IAM Service предоставляет возможности аутентификации, авторизации и управления
// пользователями с использованием JWT токенов и Casbin RBAC.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	gormlogger "gorm.io/gorm/logger"

	rediscache "github.com/andrewhigh08/iam-service/internal/adapter/cache/redis"
	"github.com/andrewhigh08/iam-service/internal/adapter/http/handler"
	"github.com/andrewhigh08/iam-service/internal/adapter/http/middleware"
	postgresrepo "github.com/andrewhigh08/iam-service/internal/adapter/repository/postgres"
	"github.com/andrewhigh08/iam-service/internal/config"
	"github.com/andrewhigh08/iam-service/internal/pkg/logger"
	"github.com/andrewhigh08/iam-service/internal/pkg/telemetry"
	"github.com/andrewhigh08/iam-service/internal/service"

	// Swagger docs / Документация Swagger.
	_ "github.com/andrewhigh08/iam-service/docs"
)

// main is the application entry point.
// main является точкой входа приложения.
//
// Initializes all dependencies and starts the HTTP server with graceful shutdown.
// Инициализирует все зависимости и запускает HTTP сервер с graceful shutdown.
func main() {
	// Load configuration / Загружаем конфигурацию
	// MustLoad panics if config is invalid, which is desired at startup
	// MustLoad паникует при невалидном конфиге, что желательно при запуске
	cfg := config.MustLoad()

	// Initialize logger / Инициализируем логгер
	log := logger.New(logger.Config{
		Level:     getEnv("LOG_LEVEL", "info"),
		Format:    getEnv("LOG_FORMAT", "json"),
		AddSource: true,
	})
	logger.SetDefault(log)

	// Initialize telemetry / Инициализируем телеметрию
	telemetryCfg := telemetry.Config{
		Enabled:      cfg.Telemetry.Enabled,
		OTLPEndpoint: cfg.Telemetry.OTLPEndpoint,
		ServiceName:  cfg.Telemetry.ServiceName,
		Environment:  cfg.Telemetry.Environment,
	}
	tp, err := telemetry.InitTelemetry(context.Background(), telemetryCfg)
	if err != nil {
		log.Error("failed to initialize telemetry", "error", err)
	} else if cfg.Telemetry.Enabled {
		log.Info("telemetry initialized", "endpoint", cfg.Telemetry.OTLPEndpoint)
	}

	// Initialize database connection / Инициализируем подключение к БД
	db, err := initDB(cfg, log)
	if err != nil {
		log.Fatal("failed to connect to database", "error", err)
	}

	// Initialize Redis connection / Инициализируем подключение к Redis
	redisClient := initRedis(cfg, log)

	// Initialize caches / Инициализируем кэши
	authzCache := rediscache.NewAuthorizationCache(redisClient)
	refreshTokenCache := rediscache.NewRefreshTokenCache(redisClient)
	tokenCache := rediscache.NewTokenCache(redisClient)
	rateLimitCache := rediscache.NewRateLimitCache(redisClient)

	// Initialize repositories / Инициализируем репозитории
	userRepo := postgresrepo.NewUserRepository(db)
	auditRepo := postgresrepo.NewAuditLogRepository(db)
	txManager := postgresrepo.NewTransactionManager(db)

	// Initialize services / Инициализируем сервисы
	authzService, err := service.NewAuthorizationService(db, authzCache, cfg.Casbin.ModelPath, log)
	if err != nil {
		log.Fatal("failed to initialize authorization service", "error", err)
	}

	auditService := service.NewAuditService(auditRepo, log)
	userService := service.NewUserService(userRepo, txManager, authzService, auditService, log)

	authServiceCfg := service.AuthServiceConfig{
		PrivateKeyPath:   cfg.JWT.PrivateKeyPath,
		PublicKeyPath:    cfg.JWT.PublicKeyPath,
		TokenTTL:         time.Duration(cfg.JWT.AccessTokenTTL) * time.Minute,
		RefreshTTL:       time.Duration(cfg.JWT.RefreshTokenTTL) * time.Hour,
		MaxLoginAttempts: cfg.Lockout.MaxAttempts,
		LockoutDuration:  time.Duration(cfg.Lockout.LockoutDuration) * time.Minute,
		PasswordMaxAge:   time.Duration(cfg.Password.MaxAgeDays) * 24 * time.Hour,
		DevMode:          cfg.DevMode,
	}
	authService, err := service.NewAuthService(userRepo, authzService, auditService, refreshTokenCache, tokenCache, rateLimitCache, authServiceCfg, log)
	if err != nil {
		log.Fatal("failed to initialize auth service", "error", err)
	}

	// Initialize HTTP handlers / Инициализируем HTTP обработчики
	healthHandler := handler.NewHealthHandler(db, redisClient)
	authHandler := handler.NewAuthHandler(authService, authzService, log)
	userHandler := handler.NewUserHandler(userService, log)

	// Initialize rate limiter / Инициализируем ограничитель частоты запросов
	rateLimitCfg := middleware.DefaultRateLimitConfig()
	rateLimiter := middleware.NewIPRateLimiter(rateLimitCfg)

	// Setup router with all routes / Настраиваем роутер со всеми маршрутами
	securityCfg := middleware.DefaultSecurityConfig()
	router := setupRouter(healthHandler, authHandler, userHandler, securityCfg, rateLimiter)

	// Seed database with initial data / Заполняем БД начальными данными
	seeder := service.NewSeeder(db, authzService, log)
	if err := seeder.SeedAll(context.Background()); err != nil {
		log.Error("failed to seed database", "error", err)
	}

	// Configure HTTP server / Настраиваем HTTP сервер
	srv := &http.Server{
		Addr:         ":" + cfg.Server.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second, // Max time to read request / Макс. время чтения запроса
		WriteTimeout: 15 * time.Second, // Max time to write response / Макс. время записи ответа
		IdleTimeout:  60 * time.Second, // Max time for keep-alive / Макс. время keep-alive
	}

	// Start server in goroutine / Запускаем сервер в горутине
	go func() {
		log.Info("server starting", "port", cfg.Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal("failed to start server", "error", err)
		}
	}()

	// Graceful shutdown handling / Обработка graceful shutdown
	// Wait for interrupt signal / Ожидаем сигнал прерывания
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info("shutting down server...")

	// Give outstanding requests time to complete
	// Даём время на завершение текущих запросов
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Error("server forced to shutdown", "error", err)
	}

	// Shutdown telemetry / Завершаем телеметрию
	if tp != nil {
		if err := tp.Shutdown(ctx); err != nil {
			log.Error("failed to shutdown telemetry", "error", err)
		}
	}

	// Close database connection / Закрываем подключение к БД
	if sqlDB, err := db.DB(); err == nil {
		_ = sqlDB.Close()
	}

	// Close Redis connection / Закрываем подключение к Redis
	if redisClient != nil {
		_ = redisClient.Close()
	}

	log.Info("server exited properly")
}

// initDB initializes the PostgreSQL database connection with connection pooling.
// initDB инициализирует подключение к PostgreSQL с пулом соединений.
func initDB(cfg *config.Config, log *logger.Logger) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(cfg.Database.DSN()), &gorm.Config{
		Logger: gormlogger.Default.LogMode(gormlogger.Warn),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to open database connection: %w", err)
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, fmt.Errorf("failed to get underlying sql.DB: %w", err)
	}

	// Configure connection pool / Настраиваем пул соединений
	sqlDB.SetMaxIdleConns(10)           // Max idle connections / Макс. простаивающих соединений
	sqlDB.SetMaxOpenConns(100)          // Max open connections / Макс. открытых соединений
	sqlDB.SetConnMaxLifetime(time.Hour) // Connection max lifetime / Макс. время жизни соединения

	// Verify connection with ping / Проверяем соединение пингом
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := sqlDB.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	log.Info("database connection established")
	return db, nil
}

// initRedis initializes the Redis client connection.
// initRedis инициализирует подключение клиента Redis.
func initRedis(cfg *config.Config, log *logger.Logger) *redis.Client {
	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", cfg.Redis.Host, cfg.Redis.Port),
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	// Verify connection / Проверяем соединение
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := client.Ping(ctx).Err(); err != nil {
		cancel()
		log.Fatal("failed to connect to Redis", "error", err)
	}
	cancel()

	log.Info("redis connection established")
	return client
}

// setupRouter configures the Gin router with all routes and middleware.
// setupRouter настраивает роутер Gin со всеми маршрутами и middleware.
func setupRouter(
	healthHandler *handler.HealthHandler,
	authHandler *handler.AuthHandler,
	userHandler *handler.UserHandler,
	securityCfg middleware.SecurityConfig,
	rateLimiter *middleware.IPRateLimiter,
) *gin.Engine {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()

	// Configure trusted proxies to prevent IP spoofing via X-Forwarded-For
	// Настраиваем доверенные прокси для предотвращения IP-спуфинга через X-Forwarded-For
	// Only trust localhost proxies by default. Add your load balancer IPs in production.
	// По умолчанию доверяем только localhost прокси. Добавьте IP балансировщика в продакшене.
	if err := router.SetTrustedProxies([]string{"127.0.0.1", "::1"}); err != nil {
		logger.Default().Error("failed to set trusted proxies", "error", err)
	}

	// Global middleware / Глобальные middleware
	router.Use(gin.Recovery())                              // Panic recovery / Восстановление после паники
	router.Use(middleware.RequestID())                      // Request ID / ID запроса
	router.Use(middleware.SecurityHeaders(securityCfg))     // Security headers / Заголовки безопасности
	router.Use(middleware.CORS(securityCfg))                // CORS / Кросс-доменные запросы
	router.Use(middleware.RateLimitMiddleware(rateLimiter)) // Global rate limiting / Глобальное ограничение частоты
	router.Use(middleware.Metrics())                        // Prometheus metrics / Метрики Prometheus
	router.Use(requestLogger())                             // Request logging / Логирование запросов

	// Health check endpoints for Kubernetes probes
	// Эндпоинты проверки здоровья для Kubernetes проб
	router.GET("/health", healthHandler.Health)
	router.GET("/health/live", healthHandler.Live)
	router.GET("/health/ready", healthHandler.Ready)

	// Metrics endpoint for Prometheus / Эндпоинт метрик для Prometheus
	handler.RegisterMetrics(router)

	// Swagger documentation / Документация Swagger
	handler.RegisterSwagger(router)

	// Public authentication endpoints / Публичные эндпоинты аутентификации
	auth := router.Group("/auth")
	// Login has stricter rate limiting to prevent brute-force attacks
	// Login имеет более строгий лимит для защиты от brute-force атак
	auth.POST("/login", middleware.LoginRateLimitMiddleware(rateLimiter), authHandler.Login)
	auth.POST("/first-time-password-change", authHandler.FirstTimePasswordChange)
	auth.POST("/refresh", authHandler.RefreshToken) // Refresh access token / Обновить access токен
	auth.POST("/logout", authHandler.Logout)        // Logout (invalidate refresh token) / Выход (инвалидировать refresh токен)

	// Protected API endpoints (require authentication)
	// Защищённые API эндпоинты (требуют аутентификации)
	api := router.Group("/api/v1")
	api.Use(authHandler.AuthMiddleware())

	// Password change (available to all authenticated users)
	// Смена пароля (доступна всем аутентифицированным пользователям)
	api.POST("/change-password", authHandler.ChangePassword)
	api.POST("/logout-all", authHandler.LogoutAll) // Logout from all devices / Выход со всех устройств

	// Session management endpoints (available to all authenticated users)
	// Эндпоинты управления сессиями (доступны всем аутентифицированным пользователям)
	api.GET("/sessions", authHandler.GetSessions)          // List active sessions / Список активных сессий
	api.DELETE("/sessions/:id", authHandler.RevokeSession) // Revoke a session / Отозвать сессию

	// User management endpoints / Эндпоинты управления пользователями
	users := api.Group("/users")
	users.GET("", authHandler.RBACMiddleware("users", "read"), userHandler.ListUsers)
	users.GET("/:id", authHandler.RBACMiddleware("users", "read"), userHandler.GetUser)
	users.POST("", authHandler.RBACMiddleware("users", "write"), userHandler.CreateUser)
	users.POST("/:id/block", authHandler.RBACMiddleware("users", "write"), userHandler.BlockUser)
	users.POST("/:id/unblock", authHandler.RBACMiddleware("users", "write"), userHandler.UnblockUser)

	return router
}

// requestLogger returns a middleware that logs HTTP requests.
// requestLogger возвращает middleware, которое логирует HTTP запросы.
func requestLogger() gin.HandlerFunc {
	log := logger.Default()
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path

		// Process request / Обрабатываем запрос
		c.Next()

		// Log after request completion / Логируем после завершения запроса
		log.LogRequest(
			c.Request.Method,
			path,
			c.Writer.Status(),
			time.Since(start),
			c.ClientIP(),
		)
	}
}

// getEnv returns environment variable value or default if not set.
// getEnv возвращает значение переменной окружения или значение по умолчанию.
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
