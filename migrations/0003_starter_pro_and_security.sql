-- ====================================================================
-- ALMAI PRODUCTS — Migration 0003
-- 1. Rename Starter Z to Starter Pro
-- 2. Create Rate Limits Table (3 attempts limit enforcement)
-- ====================================================================

-- 1. Update Package Name to Starter Pro
UPDATE packages SET name = 'Starter Pro' WHERE slug = 'starter' OR name = 'Starter Z';

-- 2. Rate Limits Table for IP and Email Authentication Throttling
CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT PRIMARY KEY,
    attempts INTEGER NOT NULL DEFAULT 1,
    last_attempt INTEGER NOT NULL,
    blocked_until INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_key ON rate_limits(key);
