-- ═══════════════════════════════════════
-- Запустить в Supabase Dashboard → SQL Editor
-- ═══════════════════════════════════════

-- Клиенты (подписчики)
CREATE TABLE IF NOT EXISTS clients (
    id BIGSERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL DEFAULT '',
    current_ip_enc TEXT,          -- Fernet-зашифрованный IP
    current_ip_hash TEXT,         -- SHA-256 хэш для поиска
    previous_ip_enc TEXT,         -- Предыдущий IP (зашифрованный)
    last_activated_at TIMESTAMPTZ,
    activations_today INT NOT NULL DEFAULT 0,
    activations_reset_date DATE,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_clients_token ON clients(token);
CREATE INDEX IF NOT EXISTS idx_clients_ip_hash ON clients(current_ip_hash);

-- Relay-серверы
CREATE TABLE IF NOT EXISTS relays (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,            -- IP или домен relay
    agent_port INT NOT NULL DEFAULT 7580,
    agent_secret TEXT NOT NULL DEFAULT '',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_synced BOOLEAN NOT NULL DEFAULT TRUE,
    last_health JSONB,            -- последний /health ответ
    last_health_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Лог активаций
CREATE TABLE IF NOT EXISTS activation_log (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    ip_enc TEXT NOT NULL,          -- зашифрованный IP
    user_agent TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_activation_log_client ON activation_log(client_id);
CREATE INDEX IF NOT EXISTS idx_activation_log_date ON activation_log(created_at);

-- IP-блэклист (хард-бан по IP)
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id BIGSERIAL PRIMARY KEY,
    ip_hash TEXT UNIQUE NOT NULL,  -- SHA-256 хэш для быстрого поиска
    ip_enc TEXT NOT NULL,          -- Fernet-зашифрованный IP (для отображения)
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ip_blacklist_hash ON ip_blacklist(ip_hash);

-- ═══════════════════════════════════════
-- RLS (Row Level Security)
-- Доступ только через service_role key
-- ═══════════════════════════════════════
ALTER TABLE clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE relays ENABLE ROW LEVEL SECURITY;
ALTER TABLE activation_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_blacklist ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Service role full access" ON clients FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON relays FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON activation_log FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON ip_blacklist FOR ALL USING (true) WITH CHECK (true);