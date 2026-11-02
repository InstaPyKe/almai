-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0005
-- 45% Referral Downlines Tracking & Monetization System
-- ====================================================================

-- 1. Add Referral Code and Referrer link to Users Table
ALTER TABLE users ADD COLUMN referral_code TEXT;
ALTER TABLE users ADD COLUMN referred_by TEXT;

-- 2. Create Referrals Tracking Table
CREATE TABLE IF NOT EXISTS referrals (
    id TEXT PRIMARY KEY,
    referrer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    referred_user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    referral_code TEXT,
    status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered', 'active_paid')),
    package_id TEXT REFERENCES packages(id),
    package_name TEXT,
    package_price_ksh INTEGER DEFAULT 0,
    commission_rate REAL DEFAULT 0.45,
    commission_amount_ksh INTEGER DEFAULT 0,
    commission_paid INTEGER DEFAULT 0,
    created_at INTEGER NOT NULL,
    activated_at INTEGER
);

CREATE INDEX IF NOT EXISTS idx_referrals_referrer ON referrals(referrer_id);
CREATE INDEX IF NOT EXISTS idx_referrals_referred ON referrals(referred_user_id);
CREATE INDEX IF NOT EXISTS idx_referrals_status ON referrals(status);

-- 3. Populate default unique referral codes for existing users
UPDATE users 
SET referral_code = 'ALM' || UPPER(SUBSTR(REPLACE(REPLACE(id, 'usr_', ''), 'admin_', ''), 1, 6)) 
WHERE referral_code IS NULL;

