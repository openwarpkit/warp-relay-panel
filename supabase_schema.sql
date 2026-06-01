-- ═══════════════════════════════════════════════════════════════
-- WARP Relay Panel - single Supabase schema (source of truth)
-- Run in Supabase Dashboard -> SQL Editor.
-- Idempotent: safe to run multiple times.
-- ═══════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════
-- TABLES
-- ═══════════════════════════════════════

-- Clients (subscribers)
CREATE TABLE IF NOT EXISTS clients (
    id BIGSERIAL PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    current_ip_enc TEXT,            -- Fernet-encrypted IP
    current_ip_hash TEXT,           -- SHA-256 hash for lookup
    previous_ip_enc TEXT,           -- previous IP (encrypted)
    previous_ip_hash TEXT,          -- SHA-256 hash of previous IP
    last_activated_at TIMESTAMPTZ,
    is_blocked BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Relay servers
CREATE TABLE IF NOT EXISTS relays (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    host TEXT NOT NULL,             -- IP or domain of relay
    agent_port INT NOT NULL DEFAULT 7580,
    agent_secret TEXT NOT NULL DEFAULT '',
    agent_type TEXT NOT NULL DEFAULT 'full',
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_synced BOOLEAN NOT NULL DEFAULT TRUE,
    last_health JSONB,              -- last /health response
    last_health_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'relays_agent_type_check'
  ) THEN
    ALTER TABLE relays
      ADD CONSTRAINT relays_agent_type_check
      CHECK (agent_type IN ('full', 'min'));
  END IF;
END $$;

-- Activation log
CREATE TABLE IF NOT EXISTS activation_log (
    id BIGSERIAL PRIMARY KEY,
    client_id BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    ip_enc TEXT NOT NULL,           -- encrypted IP
    ip_hash TEXT,                   -- SHA-256 hash for lookup
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- IP blacklist (hard-ban by IP)
CREATE TABLE IF NOT EXISTS ip_blacklist (
    id BIGSERIAL PRIMARY KEY,
    ip_hash TEXT UNIQUE NOT NULL,   -- SHA-256 hash for fast lookup
    ip_enc TEXT NOT NULL,           -- Fernet-encrypted IP (for display)
    reason TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Rate-limits per IP (Mbps + optional TTL)
CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGSERIAL PRIMARY KEY,
    ip_hash TEXT UNIQUE NOT NULL,
    ip_enc TEXT NOT NULL,
    mbps NUMERIC(10,2) NOT NULL CHECK (mbps > 0),
    reason TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,         -- NULL = forever
    client_id BIGINT REFERENCES clients(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- ═══════════════════════════════════════
-- INDEXES
-- ═══════════════════════════════════════

CREATE INDEX IF NOT EXISTS idx_clients_token         ON clients(token);
CREATE INDEX IF NOT EXISTS idx_clients_ip_hash       ON clients(current_ip_hash);
CREATE INDEX IF NOT EXISTS idx_clients_prev_ip_hash  ON clients(previous_ip_hash);
-- partial: 90%+ clients are not blocked
CREATE INDEX IF NOT EXISTS idx_clients_active        ON clients(id) WHERE is_blocked = FALSE;

CREATE INDEX IF NOT EXISTS idx_relays_active         ON relays(id) WHERE is_active = TRUE;
-- partial for hot path get_active_relays(agent_type='full')
CREATE INDEX IF NOT EXISTS idx_relays_active_full    ON relays(id) WHERE is_active = TRUE AND agent_type = 'full';

CREATE INDEX IF NOT EXISTS idx_activation_log_client   ON activation_log(client_id);
CREATE INDEX IF NOT EXISTS idx_activation_log_date     ON activation_log(created_at);
CREATE INDEX IF NOT EXISTS idx_activation_log_ip_hash  ON activation_log(ip_hash);

CREATE INDEX IF NOT EXISTS idx_ip_blacklist_hash     ON ip_blacklist(ip_hash);

CREATE INDEX IF NOT EXISTS idx_rate_limits_hash      ON rate_limits(ip_hash);
-- partial: only active with TTL - for /api/rate-limits/expired
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires   ON rate_limits(expires_at) WHERE expires_at IS NOT NULL;


-- ═══════════════════════════════════════
-- RLS - access only via service_role key
-- ═══════════════════════════════════════
ALTER TABLE clients        ENABLE ROW LEVEL SECURITY;
ALTER TABLE relays         ENABLE ROW LEVEL SECURITY;
ALTER TABLE activation_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_blacklist   ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits    ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access" ON clients;
DROP POLICY IF EXISTS "Service role full access" ON relays;
DROP POLICY IF EXISTS "Service role full access" ON activation_log;
DROP POLICY IF EXISTS "Service role full access" ON ip_blacklist;
DROP POLICY IF EXISTS "Service role full access" ON rate_limits;

CREATE POLICY "Service role full access" ON clients        FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON relays         FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON activation_log FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON ip_blacklist   FOR ALL USING (true) WITH CHECK (true);
CREATE POLICY "Service role full access" ON rate_limits    FOR ALL USING (true) WITH CHECK (true);


-- ═══════════════════════════════════════════════════════════════
-- RPC FUNCTIONS
-- ═══════════════════════════════════════════════════════════════

-- ═══════════════════════════════════════
-- activate_client_atomic
-- Activation by token. Atomic: ban check -> same IP check ->
-- update clients -> insert activation_log -> return rate_limit.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION activate_client_atomic(
  p_token         TEXT,
  p_new_ip_enc    TEXT,
  p_new_ip_hash   TEXT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client            clients%ROWTYPE;
  v_old_ip_enc        TEXT;
  v_old_ip_hash       TEXT;
  v_old_ip_shared     BOOLEAN := FALSE;
  v_others_count      INT;
  v_ban_reason        TEXT;
  v_rate_limit        JSONB := NULL;
BEGIN
  SELECT * INTO v_client FROM clients WHERE token = p_token;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'invalid_token');
  END IF;

  IF v_client.is_blocked THEN
    RETURN jsonb_build_object('error', 'blocked');
  END IF;

  SELECT reason INTO v_ban_reason
    FROM ip_blacklist WHERE ip_hash = p_new_ip_hash;
  IF FOUND THEN
    RETURN jsonb_build_object('error', 'ip_banned', 'reason', v_ban_reason);
  END IF;

  -- Same IP: do not touch clients/log, but return current rate_limit
  IF v_client.current_ip_hash = p_new_ip_hash THEN
    SELECT jsonb_build_object('mbps', mbps, 'expires_at', expires_at)
      INTO v_rate_limit
    FROM rate_limits
    WHERE ip_hash = p_new_ip_hash
      AND (expires_at IS NULL OR expires_at > NOW());

    RETURN jsonb_build_object(
      'status',     'already_active',
      'client_id',  v_client.id,
      'rate_limit', v_rate_limit
    );
  END IF;

  v_old_ip_enc  := v_client.current_ip_enc;
  v_old_ip_hash := v_client.current_ip_hash;

  IF v_old_ip_hash IS NOT NULL THEN
    SELECT COUNT(*) INTO v_others_count
      FROM clients
     WHERE current_ip_hash = v_old_ip_hash
       AND id != v_client.id;
    v_old_ip_shared := (v_others_count > 0);
  END IF;

  UPDATE clients SET
    previous_ip_enc   = current_ip_enc,
    previous_ip_hash  = current_ip_hash,
    current_ip_enc    = p_new_ip_enc,
    current_ip_hash   = p_new_ip_hash,
    last_activated_at = NOW()
  WHERE id = v_client.id;

  INSERT INTO activation_log (client_id, ip_enc, ip_hash)
  VALUES (v_client.id, p_new_ip_enc, p_new_ip_hash);

  SELECT jsonb_build_object('mbps', mbps, 'expires_at', expires_at)
    INTO v_rate_limit
  FROM rate_limits
  WHERE ip_hash = p_new_ip_hash
    AND (expires_at IS NULL OR expires_at > NOW());

  RETURN jsonb_build_object(
    'status',        'activated',
    'client_id',     v_client.id,
    'old_ip_enc',    v_old_ip_enc,
    'old_ip_shared', v_old_ip_shared,
    'rate_limit',    v_rate_limit
  );
END;
$$;


-- ═══════════════════════════════════════
-- activate_client_by_id_atomic
-- Manual activation by id (called by bot).
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION activate_client_by_id_atomic(
  p_client_id     BIGINT,
  p_new_ip_enc    TEXT,
  p_new_ip_hash   TEXT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client            clients%ROWTYPE;
  v_old_ip_enc        TEXT;
  v_old_ip_hash       TEXT;
  v_old_ip_shared     BOOLEAN := FALSE;
  v_others_count      INT;
  v_ban_reason        TEXT;
  v_rate_limit        JSONB := NULL;
BEGIN
  SELECT * INTO v_client FROM clients WHERE id = p_client_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'client_not_found');
  END IF;

  IF v_client.is_blocked THEN
    RETURN jsonb_build_object('error', 'blocked');
  END IF;

  SELECT reason INTO v_ban_reason
    FROM ip_blacklist WHERE ip_hash = p_new_ip_hash;
  IF FOUND THEN
    RETURN jsonb_build_object('error', 'ip_banned', 'reason', v_ban_reason);
  END IF;

  IF v_client.current_ip_hash = p_new_ip_hash THEN
    SELECT jsonb_build_object('mbps', mbps, 'expires_at', expires_at)
      INTO v_rate_limit
    FROM rate_limits
    WHERE ip_hash = p_new_ip_hash
      AND (expires_at IS NULL OR expires_at > NOW());

    RETURN jsonb_build_object(
      'status',     'already_active',
      'client_id',  v_client.id,
      'rate_limit', v_rate_limit
    );
  END IF;

  v_old_ip_enc  := v_client.current_ip_enc;
  v_old_ip_hash := v_client.current_ip_hash;

  IF v_old_ip_hash IS NOT NULL THEN
    SELECT COUNT(*) INTO v_others_count
      FROM clients
     WHERE current_ip_hash = v_old_ip_hash
       AND id != v_client.id;
    v_old_ip_shared := (v_others_count > 0);
  END IF;

  UPDATE clients SET
    previous_ip_enc   = current_ip_enc,
    previous_ip_hash  = current_ip_hash,
    current_ip_enc    = p_new_ip_enc,
    current_ip_hash   = p_new_ip_hash,
    last_activated_at = NOW()
  WHERE id = v_client.id;

  INSERT INTO activation_log (client_id, ip_enc, ip_hash)
  VALUES (v_client.id, p_new_ip_enc, p_new_ip_hash);

  SELECT jsonb_build_object('mbps', mbps, 'expires_at', expires_at)
    INTO v_rate_limit
  FROM rate_limits
  WHERE ip_hash = p_new_ip_hash
    AND (expires_at IS NULL OR expires_at > NOW());

  RETURN jsonb_build_object(
    'status',        'activated',
    'client_id',     v_client.id,
    'old_ip_enc',    v_old_ip_enc,
    'old_ip_shared', v_old_ip_shared,
    'rate_limit',    v_rate_limit
  );
END;
$$;


-- ═══════════════════════════════════════
-- block_client_atomic
-- UPDATE + flags (current_ip_banned, previous_ip_banned, current_ip_shared)
-- in one query.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION block_client_atomic(
  p_client_id BIGINT,
  p_blocked   BOOLEAN
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client             clients%ROWTYPE;
  v_current_ip_banned  BOOLEAN := FALSE;
  v_previous_ip_banned BOOLEAN := FALSE;
  v_others_count       INT     := 0;
  v_current_ip_shared  BOOLEAN := FALSE;
BEGIN
  UPDATE clients SET is_blocked = p_blocked
   WHERE id = p_client_id
   RETURNING * INTO v_client;

  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_client.current_ip_hash IS NOT NULL THEN
    v_current_ip_banned := EXISTS (
      SELECT 1 FROM ip_blacklist WHERE ip_hash = v_client.current_ip_hash
    );
    SELECT COUNT(*) INTO v_others_count
      FROM clients
     WHERE current_ip_hash = v_client.current_ip_hash
       AND id != p_client_id;
    v_current_ip_shared := (v_others_count > 0);
  END IF;

  IF v_client.previous_ip_hash IS NOT NULL THEN
    v_previous_ip_banned := EXISTS (
      SELECT 1 FROM ip_blacklist WHERE ip_hash = v_client.previous_ip_hash
    );
  END IF;

  RETURN jsonb_build_object(
    'id',                  v_client.id,
    'token',               v_client.token,
    'label',               v_client.label,
    'current_ip_enc',      v_client.current_ip_enc,
    'previous_ip_enc',     v_client.previous_ip_enc,
    'last_activated_at',   v_client.last_activated_at,
    'is_blocked',          v_client.is_blocked,
    'created_at',          v_client.created_at,
    'current_ip_banned',   v_current_ip_banned,
    'previous_ip_banned',  v_previous_ip_banned,
    'current_ip_shared',   v_current_ip_shared
  );
END;
$$;


-- ═══════════════════════════════════════
-- delete_client_atomic
-- Deletion + return data to cleanup relay.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION delete_client_atomic(
  p_client_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client            clients%ROWTYPE;
  v_others_count      INT     := 0;
  v_current_ip_shared BOOLEAN := FALSE;
BEGIN
  SELECT * INTO v_client FROM clients WHERE id = p_client_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_client.current_ip_hash IS NOT NULL THEN
    SELECT COUNT(*) INTO v_others_count
      FROM clients
     WHERE current_ip_hash = v_client.current_ip_hash
       AND id != p_client_id;
    v_current_ip_shared := (v_others_count > 0);
  END IF;

  DELETE FROM activation_log WHERE client_id = p_client_id;
  DELETE FROM clients        WHERE id        = p_client_id;

  RETURN jsonb_build_object(
    'deleted',           TRUE,
    'id',                p_client_id,
    'current_ip_enc',    v_client.current_ip_enc,
    'current_ip_shared', v_current_ip_shared
  );
END;
$$;


-- ═══════════════════════════════════════
-- get_client_full_with_bans
-- Client + ban flags for current/previous IP + current rate_limit.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION get_client_full_with_bans(
  p_client_id BIGINT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client             clients%ROWTYPE;
  v_current_ip_banned  BOOLEAN := FALSE;
  v_previous_ip_banned BOOLEAN := FALSE;
  v_rate_limit         JSONB   := NULL;
BEGIN
  SELECT * INTO v_client FROM clients WHERE id = p_client_id;
  IF NOT FOUND THEN
    RETURN jsonb_build_object('error', 'not_found');
  END IF;

  IF v_client.current_ip_hash IS NOT NULL THEN
    v_current_ip_banned := EXISTS (
      SELECT 1 FROM ip_blacklist WHERE ip_hash = v_client.current_ip_hash
    );
    SELECT jsonb_build_object('mbps', mbps, 'expires_at', expires_at)
      INTO v_rate_limit
    FROM rate_limits
    WHERE ip_hash = v_client.current_ip_hash
      AND (expires_at IS NULL OR expires_at > NOW());
  END IF;

  IF v_client.previous_ip_hash IS NOT NULL THEN
    v_previous_ip_banned := EXISTS (
      SELECT 1 FROM ip_blacklist WHERE ip_hash = v_client.previous_ip_hash
    );
  END IF;

  RETURN jsonb_build_object(
    'id',                 v_client.id,
    'token',              v_client.token,
    'label',              v_client.label,
    'current_ip_enc',     v_client.current_ip_enc,
    'previous_ip_enc',    v_client.previous_ip_enc,
    'last_activated_at',  v_client.last_activated_at,
    'is_blocked',         v_client.is_blocked,
    'created_at',         v_client.created_at,
    'current_ip_banned',  v_current_ip_banned,
    'previous_ip_banned', v_previous_ip_banned,
    'rate_limit',         v_rate_limit
  );
END;
$$;


-- ═══════════════════════════════════════
-- get_client_labels
-- Batch-resolve id -> label. Accepts array in JSON-body,
-- avoids URL length limits (unlike ?id=in.(...)).
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION get_client_labels(p_ids BIGINT[])
RETURNS TABLE (id BIGINT, label TEXT)
LANGUAGE sql
STABLE
AS $$
  SELECT id, label
    FROM clients
   WHERE id = ANY(p_ids);
$$;


-- ═══════════════════════════════════════
-- add_ip_ban_idempotent
-- INSERT ON CONFLICT DO NOTHING - without race condition.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION add_ip_ban_idempotent(
  p_ip_hash TEXT,
  p_ip_enc  TEXT,
  p_reason  TEXT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_id      BIGINT;
  v_already BOOLEAN := FALSE;
BEGIN
  INSERT INTO ip_blacklist (ip_hash, ip_enc, reason)
  VALUES (p_ip_hash, p_ip_enc, p_reason)
  ON CONFLICT (ip_hash) DO NOTHING
  RETURNING id INTO v_id;

  IF v_id IS NULL THEN
    SELECT id INTO v_id FROM ip_blacklist WHERE ip_hash = p_ip_hash;
    v_already := TRUE;
  END IF;

  RETURN jsonb_build_object(
    'id',             v_id,
    'already_exists', v_already
  );
END;
$$;


-- ═══════════════════════════════════════
-- get_sync_payload
-- Full payload for agent (startup-resync, /sync).
-- Accounts for block, IP ban, current rate_limit.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION get_sync_payload()
RETURNS TABLE (
  client_id              BIGINT,
  current_ip_enc         TEXT,
  rate_limit_mbps        NUMERIC,
  rate_limit_expires_at  TIMESTAMPTZ
)
LANGUAGE sql
STABLE
AS $$
  SELECT
    c.id            AS client_id,
    c.current_ip_enc,
    rl.mbps         AS rate_limit_mbps,
    rl.expires_at   AS rate_limit_expires_at
  FROM clients c
  LEFT JOIN rate_limits rl
    ON rl.ip_hash = c.current_ip_hash
   AND (rl.expires_at IS NULL OR rl.expires_at > NOW())
  WHERE c.is_blocked        = FALSE
    AND c.current_ip_enc   IS NOT NULL
    AND c.current_ip_hash  IS NOT NULL
    AND NOT EXISTS (
      SELECT 1 FROM ip_blacklist b
       WHERE b.ip_hash = c.current_ip_hash
    );
$$;


-- ═══════════════════════════════════════
-- get_expired_rate_limits
-- For external scheduler: everything that needs to be removed.
-- NULL expires_at - permanent, not returned.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION get_expired_rate_limits()
RETURNS TABLE (
  id          BIGINT,
  ip_enc      TEXT,
  ip_hash     TEXT,
  mbps        NUMERIC,
  expires_at  TIMESTAMPTZ,
  client_id   BIGINT
)
LANGUAGE sql
STABLE
AS $$
  SELECT id, ip_enc, ip_hash, mbps, expires_at, client_id
    FROM rate_limits
   WHERE expires_at IS NOT NULL
     AND expires_at < NOW()
   ORDER BY expires_at ASC;
$$;


-- ═══════════════════════════════════════
-- dashboard_stats
-- All counters in one call (instead of 4 round-trips).
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION dashboard_stats()
RETURNS JSON
LANGUAGE sql
STABLE
AS $$
  SELECT json_build_object(
    'total_clients',   (SELECT COUNT(*) FROM clients),
    'active_clients',  (SELECT COUNT(*) FROM clients
                         WHERE is_blocked = FALSE
                           AND current_ip_enc IS NOT NULL),
    'blocked_clients', (SELECT COUNT(*) FROM clients WHERE is_blocked = TRUE),
    'ip_bans',         (SELECT COUNT(*) FROM ip_blacklist),
    'total_relays',    (SELECT COUNT(*) FROM relays),
    'active_relays',   (SELECT COUNT(*) FROM relays WHERE is_active = TRUE)
  );
$$;


-- ═══════════════════════════════════════
-- count_clients_on_ip
-- How many active (unblocked) clients sit on an IP.
-- Used during block/delete to check shared-IP.
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION count_clients_on_ip(
  p_ip_hash           TEXT,
  p_exclude_client_id BIGINT DEFAULT NULL
)
RETURNS INT
LANGUAGE sql
STABLE
AS $$
  SELECT COUNT(*)::INT
    FROM clients
   WHERE current_ip_hash = p_ip_hash
     AND is_blocked = FALSE
     AND (p_exclude_client_id IS NULL OR id <> p_exclude_client_id);
$$;


-- ═══════════════════════════════════════
-- find_clients_by_ip
-- Search clients by IP: current -> previous -> activation history.
-- Priority: current > previous > history (one record per client).
-- ═══════════════════════════════════════
CREATE OR REPLACE FUNCTION find_clients_by_ip(
  p_ip_hash             TEXT,
  p_include_log_history BOOLEAN DEFAULT TRUE
)
RETURNS TABLE (
  id                BIGINT,
  token             TEXT,
  label             TEXT,
  current_ip_enc    TEXT,
  current_ip_hash   TEXT,
  previous_ip_enc   TEXT,
  previous_ip_hash  TEXT,
  last_activated_at TIMESTAMPTZ,
  is_blocked        BOOLEAN,
  created_at        TIMESTAMPTZ,
  match_source      TEXT
)
LANGUAGE sql
STABLE
AS $$
  WITH matches AS (
    SELECT c.*, 'current' AS match_source, 1 AS priority
      FROM clients c
     WHERE c.current_ip_hash = p_ip_hash

    UNION ALL

    SELECT c.*, 'previous' AS match_source, 2 AS priority
      FROM clients c
     WHERE c.previous_ip_hash = p_ip_hash
       AND c.current_ip_hash IS DISTINCT FROM p_ip_hash

    UNION ALL

    SELECT c.*, 'history' AS match_source, 3 AS priority
      FROM clients c
     WHERE p_include_log_history
       AND c.current_ip_hash IS DISTINCT FROM p_ip_hash
       AND (c.previous_ip_hash IS DISTINCT FROM p_ip_hash OR c.previous_ip_hash IS NULL)
       AND EXISTS (
         SELECT 1 FROM activation_log al
          WHERE al.client_id = c.id AND al.ip_hash = p_ip_hash
       )
  ),
  ranked AS (
    SELECT DISTINCT ON (m.id) m.*
      FROM matches m
     ORDER BY m.id, m.priority
  )
  SELECT
    r.id, r.token, r.label,
    r.current_ip_enc, r.current_ip_hash,
    r.previous_ip_enc, r.previous_ip_hash,
    r.last_activated_at, r.is_blocked, r.created_at, r.match_source
  FROM ranked r
  ORDER BY r.priority, r.id;
$$;
