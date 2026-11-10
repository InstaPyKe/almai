-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0008
-- Paid Consumer Surveys & Dedicated Survey Earnings Ledger
-- ====================================================================

-- 1. Add surveys_balance_ksh to wallets ledger
ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0;

-- 2. Surveys definition table
CREATE TABLE IF NOT EXISTS surveys (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    category TEXT NOT NULL DEFAULT 'Consumer Habits',
    description TEXT NOT NULL,
    reward_ksh INTEGER NOT NULL DEFAULT 60,
    estimated_minutes INTEGER NOT NULL DEFAULT 3,
    questions TEXT NOT NULL, -- JSON array: [{ id, text, options: [string, ...] }]
    target_package_id TEXT, -- NULL for all registered users / partners
    is_active INTEGER NOT NULL DEFAULT 1,
    completions_count INTEGER NOT NULL DEFAULT 0,
    max_completions INTEGER DEFAULT 5000,
    created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_surveys_active ON surveys(is_active);
CREATE INDEX IF NOT EXISTS idx_surveys_created ON surveys(created_at DESC);

-- 3. Survey responses & payout tracking table
CREATE TABLE IF NOT EXISTS survey_responses (
    id TEXT PRIMARY KEY,
    survey_id TEXT NOT NULL REFERENCES surveys(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    answers TEXT NOT NULL, -- JSON object: { [questionId]: selectedOption }
    reward_amount_ksh INTEGER NOT NULL,
    completed_at INTEGER NOT NULL,
    UNIQUE(survey_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_survey_responses_user ON survey_responses(user_id);
CREATE INDEX IF NOT EXISTS idx_survey_responses_survey ON survey_responses(survey_id);

