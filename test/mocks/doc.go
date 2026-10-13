// Package mocks holds gomock mocks generated from the interfaces in internal/port.
// Regenerate them with "go generate ./test/mocks/...".
package mocks

//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/repository.go -destination=mock_repository.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/tx.go -destination=mock_tx.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/session.go -destination=mock_session.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/revocation.go -destination=mock_revocation.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/loginattempts.go -destination=mock_loginattempts.go -package=mocks
//go:generate go run go.uber.org/mock/mockgen@v0.6.0 -source=../../internal/port/service.go -destination=mock_service.go -package=mocks
