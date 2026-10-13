APP        := iam-service
MODULE     := github.com/andrewhigh08/iam-service
VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS    := -s -w -X main.version=$(VERSION)
GOLANGCI   := go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0

.DEFAULT_GOAL := help

.PHONY: help build run test test-integration test-all cover bench lint fmt generate \
        up down logs docker-build vuln clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

## Build

build: ## Build static binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/$(APP) ./cmd/api

run: ## Run the API locally (needs Postgres and Redis, see .env.example)
	go run ./cmd/api

## Test

test: ## Unit tests with race detector and coverage (integration suite is skipped by -short)
	go test -race -short -count=1 -coverprofile=coverage.out -covermode=atomic ./...

test-integration: ## Integration tests against real Postgres and Redis (needs Docker)
	go test -race -count=1 -timeout 10m ./test/integration/...

test-all: test test-integration ## Unit + integration tests

cover: test ## Open HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@go tool cover -func=coverage.out | tail -n 1

bench: ## Run benchmarks
	go test -run '^$$' -bench . -benchmem ./internal/...

## Quality

lint: ## Run golangci-lint
	$(GOLANGCI) run ./...

fmt: ## Format code
	$(GOLANGCI) fmt ./...

generate: ## Regenerate mocks and swagger docs
	go generate ./...

vuln: ## Check dependencies for known vulnerabilities
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

## Docker

up: ## Start the full stack (API, Postgres, Redis, Prometheus, Grafana, Jaeger)
	docker compose up -d --build

down: ## Stop the stack and remove volumes
	docker compose down -v

logs: ## Tail API logs
	docker compose logs -f iam-service

docker-build: ## Build the Docker image
	docker build --build-arg VERSION=$(VERSION) -t $(APP):$(VERSION) -t $(APP):latest .

## Misc

clean: ## Remove build and test artifacts
	rm -rf bin/ coverage.out coverage.html
