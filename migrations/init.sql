-- Таблица пользователей
-- Таблица пользователей
CREATE TABLE IF NOT EXISTS users (
    id BIGSERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    password_type VARCHAR(20) DEFAULT 'permanent' NOT NULL,
    password_changed_at TIMESTAMP,
    full_name VARCHAR(255),
    is_blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP
);

-- Добавление колонки password_changed_at если она не существует (для существующих БД)
ALTER TABLE users ADD COLUMN IF NOT EXISTS password_changed_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_deleted_at ON users(deleted_at);

-- Таблица audit logs
CREATE TABLE IF NOT EXISTS audit_logs (
    id BIGSERIAL PRIMARY KEY,
    user_id BIGINT NOT NULL,
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(50),
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_logs(created_at);

-- Таблица политик Casbin (создается автоматически gorm-adapter, но можем определить явно)
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

CREATE INDEX IF NOT EXISTS idx_casbin_rule ON casbin_rule(ptype, v0, v1);

-- Seed: базовые политики
INSERT INTO casbin_rule (ptype, v0, v1, v2) VALUES
    ('p', 'role:admin', 'users', 'read'),
    ('p', 'role:admin', 'users', 'write'),
    ('p', 'role:admin', 'users', 'delete'),
    ('p', 'role:admin', 'audit', 'read'),
    ('p', 'role:user', 'users', 'read'),
    ('p', 'role:user', 'profile', 'write'),
    ('p', 'role:viewer', 'users', 'read')
ON CONFLICT DO NOTHING;

-- Первый администратор (email: admin@example.com, пароль: Admin123!)
INSERT INTO users (email, password_hash, full_name, is_blocked) VALUES
    ('admin@example.com', '$2a$10$/X1SAHXbl1RiW9wJmGWKKeLTgYMCj.oIePN4gFwc/zuYDBzLsx5PO', 'System Administrator', false)
ON CONFLICT (email) DO NOTHING;

-- Назначаем роль admin первому пользователю
INSERT INTO casbin_rule (ptype, v0, v1) VALUES
    ('g', 'user:1', 'role:admin')
ON CONFLICT DO NOTHING;