CREATE TABLE IF NOT EXISTS users (
  id BIGSERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  password_temporary BOOLEAN NOT NULL DEFAULT FALSE,
  password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  full_name VARCHAR(255) NOT NULL DEFAULT '',
  is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  actor_id BIGINT NOT NULL DEFAULT 0,
  action VARCHAR(100) NOT NULL,
  resource_type VARCHAR(50) NOT NULL DEFAULT '',
  resource_id VARCHAR(255) NOT NULL DEFAULT '',
  details JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs (actor_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs (resource_type, resource_id);

CREATE TABLE IF NOT EXISTS casbin_rule (
  id BIGSERIAL PRIMARY KEY,
  ptype VARCHAR(100),
  v0 VARCHAR(100),
  v1 VARCHAR(100),
  v2 VARCHAR(100),
  v3 VARCHAR(100),
  v4 VARCHAR(100),
  v5 VARCHAR(100)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_casbin_rule ON casbin_rule (ptype, v0, v1, v2, v3, v4, v5);
