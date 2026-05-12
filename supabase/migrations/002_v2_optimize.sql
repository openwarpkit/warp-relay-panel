-- ═══════════════════════════════════════
-- v2 миграция: атомарные RPC + rate_limits
-- Применять через Supabase Dashboard → SQL Editor
-- Идемпотентна (IF NOT EXISTS / CREATE OR REPLACE)
-- ═══════════════════════════════════════

-- ───────────────────────────────────────
-- 1. Недостающие колонки
-- ───────────────────────────────────────

ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS previous_ip_hash TEXT;

ALTER TABLE activation_log
  ADD COLUMN IF NOT EXISTS ip_hash TEXT;

-- ───────────────────────────────────────
-- 2. Индексы под новые RPC
-- ───────────────────────────────────────

CREATE INDEX IF NOT EXISTS idx_clients_prev_ip_hash
  ON clients(previous_ip_hash);

CREATE INDEX IF NOT EXISTS idx_activation_log_ip_hash
  ON activation_log(ip_hash);

-- partial: 90%+ клиентов не заблокированы
CREATE INDEX IF NOT EXISTS idx_clients_active
  ON clients(id) WHERE is_blocked = FALSE;

-- partial: для get_active_relays / list_relays
CREATE INDEX IF NOT EXISTS idx_relays_active
  ON relays(id) WHERE is_active = TRUE;

-- ───────────────────────────────────────
-- 3. Таблица rate_limits
-- ───────────────────────────────────────

CREATE TABLE IF NOT EXISTS rate_limits (
    id BIGSERIAL PRIMARY KEY,
    ip_hash TEXT UNIQUE NOT NULL,
    ip_enc TEXT NOT NULL,
    mbps NUMERIC(10,2) NOT NULL CHECK (mbps > 0),
    reason TEXT NOT NULL DEFAULT '',
    expires_at TIMESTAMPTZ,                       -- NULL = бессрочно
    client_id BIGINT REFERENCES clients(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_hash
  ON rate_limits(ip_hash);

-- partial: только активные с TTL — для эндпоинта /expired
CREATE INDEX IF NOT EXISTS idx_rate_limits_expires
  ON rate_limits(expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access" ON rate_limits;
CREATE POLICY "Service role full access" ON rate_limits
  FOR ALL USING (true) WITH CHECK (true);


-- ═══════════════════════════════════════
-- RPC: activate_client_atomic
-- Заменяет 5 round-trip'ов на 1.
-- Возвращает JSONB:
--   {error: "..."}
--   {status: "already_active", client_id, rate_limit}
--   {status: "activated", client_id, old_ip_enc, old_ip_shared, rate_limit}
-- ═══════════════════════════════════════

CREATE OR REPLACE FUNCTION activate_client_atomic(
  p_token         TEXT,
  p_new_ip_enc    TEXT,
  p_new_ip_hash   TEXT,
  p_user_agent    TEXT,
  p_max_per_day   INT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client            clients%ROWTYPE;
  v_today             DATE := CURRENT_DATE;
  v_activations_today INT;
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

  v_activations_today := v_client.activations_today;
  IF v_client.activations_reset_date IS DISTINCT FROM v_today THEN
    v_activations_today := 0;
  END IF;

  IF p_max_per_day > 0 AND v_activations_today >= p_max_per_day THEN
    RETURN jsonb_build_object('error', 'daily_limit');
  END IF;

  -- Тот же IP: не трогаем clients, не пишем log, но возвращаем rate_limit
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
    previous_ip_enc        = current_ip_enc,
    previous_ip_hash       = current_ip_hash,
    current_ip_enc         = p_new_ip_enc,
    current_ip_hash        = p_new_ip_hash,
    last_activated_at      = NOW(),
    activations_today      = v_activations_today + 1,
    activations_reset_date = v_today
  WHERE id = v_client.id;

  INSERT INTO activation_log (client_id, ip_enc, ip_hash, user_agent)
  VALUES (
    v_client.id,
    p_new_ip_enc,
    p_new_ip_hash,
    NULLIF(LEFT(COALESCE(p_user_agent, ''), 500), '')
  );

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
-- RPC: activate_client_by_id_atomic
-- Ручная активация по id (вызывается ботом).
-- ═══════════════════════════════════════

CREATE OR REPLACE FUNCTION activate_client_by_id_atomic(
  p_client_id     BIGINT,
  p_new_ip_enc    TEXT,
  p_new_ip_hash   TEXT,
  p_max_per_day   INT
) RETURNS JSONB
LANGUAGE plpgsql
AS $$
DECLARE
  v_client            clients%ROWTYPE;
  v_today             DATE := CURRENT_DATE;
  v_activations_today INT;
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

  v_activations_today := v_client.activations_today;
  IF v_client.activations_reset_date IS DISTINCT FROM v_today THEN
    v_activations_today := 0;
  END IF;

  IF p_max_per_day > 0 AND v_activations_today >= p_max_per_day THEN
    RETURN jsonb_build_object('error', 'daily_limit');
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
    previous_ip_enc        = current_ip_enc,
    previous_ip_hash       = current_ip_hash,
    current_ip_enc         = p_new_ip_enc,
    current_ip_hash        = p_new_ip_hash,
    last_activated_at      = NOW(),
    activations_today      = v_activations_today + 1,
    activations_reset_date = v_today
  WHERE id = v_client.id;

  INSERT INTO activation_log (client_id, ip_enc, ip_hash, user_agent)
  VALUES (v_client.id, p_new_ip_enc, p_new_ip_hash, 'manual_bot_activation');

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
-- RPC: block_client_atomic
-- UPDATE + return клиент со флагами (current_ip_banned,
-- previous_ip_banned, current_ip_shared) одним запросом.
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
    'note',                v_client.note,
    'current_ip_enc',      v_client.current_ip_enc,
    'previous_ip_enc',     v_client.previous_ip_enc,
    'last_activated_at',   v_client.last_activated_at,
    'activations_today',   v_client.activations_today,
    'is_blocked',          v_client.is_blocked,
    'created_at',          v_client.created_at,
    'current_ip_banned',   v_current_ip_banned,
    'previous_ip_banned',  v_previous_ip_banned,
    'current_ip_shared',   v_current_ip_shared
  );
END;
$$;


-- ═══════════════════════════════════════
-- RPC: delete_client_atomic
-- Удаление клиента + возврат данных для очистки relay.
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

  -- Подсчёт ДО удаления
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
-- RPC: get_client_full_with_bans
-- Клиент + флаги бана current/previous IP + текущий rate_limit.
-- 3 запроса → 1.
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
    'id',                    v_client.id,
    'token',                 v_client.token,
    'label',                 v_client.label,
    'note',                  v_client.note,
    'current_ip_enc',        v_client.current_ip_enc,
    'previous_ip_enc',       v_client.previous_ip_enc,
    'last_activated_at',     v_client.last_activated_at,
    'activations_today',     v_client.activations_today,
    'activations_reset_date',v_client.activations_reset_date,
    'is_blocked',            v_client.is_blocked,
    'created_at',            v_client.created_at,
    'current_ip_banned',     v_current_ip_banned,
    'previous_ip_banned',    v_previous_ip_banned,
    'rate_limit',            v_rate_limit
  );
END;
$$;


-- ═══════════════════════════════════════
-- RPC: add_ip_ban_idempotent
-- INSERT ON CONFLICT DO NOTHING — без race condition
-- (раньше: SELECT existence + INSERT).
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
-- RPC: get_sync_payload
-- Полный payload для агента (startup-resync, /sync).
-- Учитывает блокировку, бан IP, актуальный rate_limit.
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
-- RPC: get_expired_rate_limits
-- Для внешнего шедулера юзера: вернуть всё, что
-- пора снять. NULL expires_at — бессрочные, не возвращаются.
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
