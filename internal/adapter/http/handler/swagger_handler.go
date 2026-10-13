package handler

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Swagger general API information.
// @title IAM Service API
// @version 1.0
// @description Identity and Access Management service: login with RS256 access tokens and rotating refresh tokens, session management, role-based authorization and user administration. Every JSON endpoint except the JWKS and health probes answers with the {success, data, error, meta} envelope.

// @contact.name API Support
// @contact.url https://github.com/andrewhigh08/iam-service

// @license.name MIT
// @license.url https://opensource.org/licenses/MIT

// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and the access token.

// RegisterSwagger mounts the Swagger UI at /swagger/*any; the spec is served from /swagger/doc.json.
// The spec names no host, so the UI calls the API through the origin of its own page.
func RegisterSwagger(router *gin.Engine) {
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler,
		ginSwagger.URL("/swagger/doc.json"),
		ginSwagger.DefaultModelsExpandDepth(-1),
		ginSwagger.PersistAuthorization(true),
	))
}
