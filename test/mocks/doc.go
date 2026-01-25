// Package mocks contains generated mock implementations for testing.
// Run `make generate-mocks` to regenerate these files.
package mocks

//go:generate mockgen -source=../../internal/port/repository.go -destination=mock_repository.go -package=mocks
//go:generate mockgen -source=../../internal/port/service.go -destination=mock_service.go -package=mocks
//go:generate mockgen -source=../../internal/port/cache.go -destination=mock_cache.go -package=mocks
