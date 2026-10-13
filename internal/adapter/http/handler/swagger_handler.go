// Package handler provides HTTP request handlers for the IAM service.
package handler

import (
	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// Swagger API documentation metadata.
// @title IAM Service API
// @version 1.0
// @description Identity and Access Management Service API
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url https://github.com/andrewhigh08/iam-service

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /
// @schemes http https

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.

// RegisterSwagger registers Swagger documentation routes.
//
// Swagger UI is available at /swagger/index.html.
func RegisterSwagger(router *gin.Engine) {
	// Serve Swagger UI at /swagger/*
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler,
		ginSwagger.URL("/swagger/doc.json"),     // URL to swagger.json
		ginSwagger.DefaultModelsExpandDepth(-1), // Hide models by default
		ginSwagger.PersistAuthorization(true),   // Remember auth token
	))
}

// SwaggerInfo holds Swagger documentation metadata.
type SwaggerInfo struct {
	Title       string // API title
	Description string // API description
	Version     string // API version
	Host        string // API host
	BasePath    string // API base path
}

// GetSwaggerInfo returns Swagger documentation info.
func GetSwaggerInfo() SwaggerInfo {
	return SwaggerInfo{
		Title:       "IAM Service API",
		Description: "Identity and Access Management Service providing authentication, authorization, and user management",
		Version:     "1.0",
		Host:        "localhost:8080",
		BasePath:    "/",
	}
}
