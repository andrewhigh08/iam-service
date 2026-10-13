package postgres

import "github.com/andrewhigh08/iam-service/internal/port"

// Compile-time checks that the adapters satisfy their ports.
var (
	_ port.TxManager          = (*TxManager)(nil)
	_ port.UserRepository     = (*UserRepository)(nil)
	_ port.AuditLogRepository = (*AuditLogRepository)(nil)
)
