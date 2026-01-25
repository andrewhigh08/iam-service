.PHONY: help build run test test-unit test-integration test-coverage lint lint-fix \
        docker-build docker-push docker-up docker-down docker-logs \
        generate-mocks generate-swagger deps clean

# Variables
APP_NAME := iam-service
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
GO_VERSION := $(shell go version | cut -d ' ' -f 3)
LDFLAGS := -ldflags "-w -s -X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

# Colors
CYAN := \033[36m
GREEN := \033[32m
YELLOW := \033[33m
RESET := \033[0m

help: ## Show this help
	@echo "$(CYAN)$(APP_NAME)$(RESET) - Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-20s$(RESET) %s\n", $$1, $$2}'

# ==================== Build ====================

build: ## Build the application binary
	@echo "$(GREEN)Building $(APP_NAME)...$(RESET)"
	@CGO_ENABLED=0 go build $(LDFLAGS) -o bin/$(APP_NAME) ./cmd/api
	@echo "$(GREEN)Build complete: bin/$(APP_NAME)$(RESET)"

run: ## Run the application locally
	@go run ./cmd/api

# ==================== Testing ====================

test: test-unit test-integration ## Run all tests

test-unit: ## Run unit tests
	@echo "$(GREEN)Running unit tests...$(RESET)"
	@go test -v -race -short ./internal/...

test-integration: ## Run integration tests
	@echo "$(GREEN)Running integration tests...$(RESET)"
	@go test -v -race -run Integration ./test/integration/...

test-coverage: ## Run tests with coverage report
	@echo "$(GREEN)Running tests with coverage...$(RESET)"
	@go test -v -race -coverprofile=coverage.out -covermode=atomic ./internal/...
	@go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -1
	@echo "$(GREEN)Coverage report: coverage.html$(RESET)"

test-bench: ## Run benchmarks
	@echo "$(GREEN)Running benchmarks...$(RESET)"
	@go test -bench=. -benchmem ./internal/...

# ==================== Linting ====================

lint: ## Run linters
	@echo "$(GREEN)Running linters...$(RESET)"
	@golangci-lint run ./...

lint-fix: ## Run linters and fix issues
	@echo "$(GREEN)Running linters with auto-fix...$(RESET)"
	@golangci-lint run --fix ./...

vet: ## Run go vet
	@go vet ./...

fmt: ## Format code
	@gofmt -s -w .
	@goimports -w .

# ==================== Code Generation ====================

generate-mocks: ## Generate mocks for interfaces
	@echo "$(GREEN)Generating mocks...$(RESET)"
	@go generate ./...
	@mockgen -source=internal/port/repository.go -destination=test/mocks/mock_repository.go -package=mocks
	@mockgen -source=internal/port/service.go -destination=test/mocks/mock_service.go -package=mocks
	@mockgen -source=internal/port/cache.go -destination=test/mocks/mock_cache.go -package=mocks
	@echo "$(GREEN)Mocks generated in test/mocks/$(RESET)"

generate-swagger: ## Generate Swagger documentation
	@echo "$(GREEN)Generating Swagger docs...$(RESET)"
	@swag init -g cmd/api/main.go -o docs
	@echo "$(GREEN)Swagger docs generated in docs/$(RESET)"

# ==================== Docker ====================

docker-build: ## Build Docker image
	@echo "$(GREEN)Building Docker image...$(RESET)"
	@docker build -t $(APP_NAME):$(VERSION) -t $(APP_NAME):latest .
	@echo "$(GREEN)Docker image built: $(APP_NAME):$(VERSION)$(RESET)"

docker-push: ## Push Docker image to registry
	@echo "$(GREEN)Pushing Docker image...$(RESET)"
	@docker push $(APP_NAME):$(VERSION)
	@docker push $(APP_NAME):latest

docker-up: ## Start all containers
	@echo "$(GREEN)Starting containers...$(RESET)"
	@docker-compose up -d
	@echo "$(GREEN)Containers started$(RESET)"

docker-down: ## Stop all containers
	@echo "$(YELLOW)Stopping containers...$(RESET)"
	@docker-compose down

docker-logs: ## Show container logs
	@docker-compose logs -f

docker-clean: ## Remove all containers and volumes
	@echo "$(YELLOW)Removing containers and volumes...$(RESET)"
	@docker-compose down -v
	@docker system prune -f

# ==================== Database ====================

migrate-up: ## Run database migrations
	@echo "$(GREEN)Running migrations...$(RESET)"
	@docker-compose exec postgres psql -U iam_user -d iam_db -f /docker-entrypoint-initdb.d/init.sql

migrate-down: ## Rollback database migrations (not implemented)
	@echo "$(YELLOW)Rollback not implemented$(RESET)"

# ==================== Dependencies ====================

deps: ## Download and tidy dependencies
	@echo "$(GREEN)Downloading dependencies...$(RESET)"
	@go mod download
	@go mod tidy
	@echo "$(GREEN)Dependencies updated$(RESET)"

deps-update: ## Update all dependencies
	@echo "$(GREEN)Updating dependencies...$(RESET)"
	@go get -u ./...
	@go mod tidy

deps-vendor: ## Vendor dependencies
	@go mod vendor

# ==================== Security ====================

security-scan: ## Run security scan
	@echo "$(GREEN)Running security scan...$(RESET)"
	@gosec -fmt=json -out=gosec-results.json ./... || true
	@echo "$(GREEN)Security scan complete: gosec-results.json$(RESET)"

vuln-check: ## Check for vulnerabilities
	@echo "$(GREEN)Checking for vulnerabilities...$(RESET)"
	@govulncheck ./...

# ==================== Utilities ====================

clean: ## Clean build artifacts
	@echo "$(YELLOW)Cleaning...$(RESET)"
	@rm -rf bin/ coverage.out coverage.html gosec-results.json
	@go clean -cache -testcache

install-tools: ## Install development tools
	@echo "$(GREEN)Installing development tools...$(RESET)"
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	@go install go.uber.org/mock/mockgen@latest
	@go install github.com/swaggo/swag/cmd/swag@latest
	@go install golang.org/x/vuln/cmd/govulncheck@latest
	@go install github.com/securego/gosec/v2/cmd/gosec@latest
	@go install golang.org/x/tools/cmd/goimports@latest
	@echo "$(GREEN)Tools installed$(RESET)"

# ==================== Info ====================

info: ## Show project info
	@echo "$(CYAN)Project Info$(RESET)"
	@echo "  App:        $(APP_NAME)"
	@echo "  Version:    $(VERSION)"
	@echo "  Go Version: $(GO_VERSION)"
	@echo "  Build Time: $(BUILD_TIME)"

.DEFAULT_GOAL := help
