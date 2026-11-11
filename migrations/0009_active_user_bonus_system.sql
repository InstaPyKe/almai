-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0009
-- Regulated Active User Bonus System & Distribution Ledger
-- ====================================================================

CREATE TABLE IF NOT EXISTS bonus_regulations (
    id TEXT PRIMARY KEY,
    is_enabled INTEGER NOT NULL DEFAULT 1,
    min_bonus_ksh INTEGER NOT NULL DEFAULT 10,
    max_bonus_per_user_ksh INTEGER NOT NULL DEFAULT 5000,
    daily_budget_cap_ksh INTEGER NOT NULL DEFAULT 100000,
    cooldown_hours INTEGER NOT NULL DEFAULT 24,
    require_active_package INTEGER NOT NULL DEFAULT 1,
    default_balance_type TEXT NOT NULL DEFAULT 'views' CHECK(default_balance_type IN ('views', 'referrals', 'surveys')),
    updated_by TEXT,
    updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS bonus_distributions (
    id TEXT PRIMARY KEY,
    campaign_title TEXT NOT NULL,
    amount_per_user_ksh INTEGER NOT NULL,
    recipient_count INTEGER NOT NULL DEFAULT 0,
    total_disbursed_ksh INTEGER NOT NULL DEFAULT 0,
    balance_type TEXT NOT NULL DEFAULT 'views',
    eligibility_scope TEXT NOT NULL DEFAULT 'active_paid',
    package_filter_id TEXT,
    min_approved_views INTEGER NOT NULL DEFAULT 0,
    admin_id TEXT REFERENCES users(id),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bonus_distributions_created ON bonus_distributions(created_at DESC);

CREATE TABLE IF NOT EXISTS bonus_recipient_logs (
    id TEXT PRIMARY KEY,
    distribution_id TEXT NOT NULL REFERENCES bonus_distributions(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    amount_ksh INTEGER NOT NULL,
    balance_type TEXT NOT NULL DEFAULT 'views',
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bonus_recipient_user ON bonus_recipient_logs(user_id, created_at DESC);

