package app

// The OpenAPI document under docs/ is generated from the handler annotations; the general
// API information lives in internal/adapter/http/handler/swagger_handler.go.
//
//go:generate go run github.com/swaggo/swag/cmd/swag@v1.16.6 init --generalInfo swagger_handler.go --dir ../adapter/http/handler --output ../../docs --parseDependency --parseInternal
