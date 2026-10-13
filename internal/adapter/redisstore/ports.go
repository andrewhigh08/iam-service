package redisstore

import "github.com/andrewhigh08/iam-service/internal/port"

// Compile-time checks that the stores satisfy their ports.
var (
	_ port.SessionStore      = (*SessionStore)(nil)
	_ port.RevocationStore   = (*RevocationStore)(nil)
	_ port.LoginAttemptStore = (*LoginAttemptStore)(nil)
)
