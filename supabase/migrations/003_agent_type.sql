-- ═══════════════════════════════════════
-- v2.6 миграция: тип relay-агента
--   'full' — обычный (whitelist + per-IP rate-limit)
--   'min'  — без whitelist, общий лимит 25 Mbps на каждый активный IP
-- ═══════════════════════════════════════

ALTER TABLE relays
  ADD COLUMN IF NOT EXISTS agent_type TEXT NOT NULL DEFAULT 'full';

-- Constraint добавляем отдельным шагом (IF NOT EXISTS на CHECK не работает напрямую)
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint
    WHERE conname = 'relays_agent_type_check'
  ) THEN
    ALTER TABLE relays
      ADD CONSTRAINT relays_agent_type_check
      CHECK (agent_type IN ('full', 'min'));
  END IF;
END $$;

-- Partial index для горячего пути:
-- get_active_relays(agent_type='full') — самый частый запрос (whitelist/rate-limit fan-out)
CREATE INDEX IF NOT EXISTS idx_relays_active_full
  ON relays(id) WHERE is_active = TRUE AND agent_type = 'full';
