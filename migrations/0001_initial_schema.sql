-- ====================================================================
-- ALMAI ADS PRODUCTS — Cloudflare D1 Database Initial Schema
-- Migration: 0001_initial_schema.sql
-- Currency: Kenyan Shillings (KSh) stored as integer units
-- ====================================================================

-- 1. Users Table
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'admin')),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'suspended')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);

-- 2. Sessions Table (Secure, unpredictable tokens)
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);

-- 3. Packages Table
CREATE TABLE IF NOT EXISTS packages (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    slug TEXT NOT NULL UNIQUE,
    price_ksh INTEGER NOT NULL,
    reward_per_view_ksh INTEGER NOT NULL,
    max_views_per_task INTEGER NOT NULL DEFAULT 100,
    features TEXT NOT NULL, -- JSON array of strings
    badge TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);

-- 4. User Active Packages Table
CREATE TABLE IF NOT EXISTS user_packages (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    package_id TEXT NOT NULL REFERENCES packages(id),
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'expired', 'pending_verification')),
    activated_at INTEGER NOT NULL,
    expires_at INTEGER
);
CREATE INDEX IF NOT EXISTS idx_user_packages_user_id ON user_packages(user_id);

-- 5. Active Advertising Campaigns Table
CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    brand_name TEXT NOT NULL,
    description TEXT NOT NULL,
    target_link TEXT,
    guidelines TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'paused', 'completed')),
    created_at INTEGER NOT NULL
);

-- 6. Task Evidence Table (Stores verified base64 image data)
CREATE TABLE IF NOT EXISTS task_evidence (
    id TEXT PRIMARY KEY,
    file_name TEXT NOT NULL,
    file_type TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    data_base64 TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

-- 7. Task Submissions Table
CREATE TABLE IF NOT EXISTS task_submissions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    campaign_id TEXT REFERENCES campaigns(id),
    package_id TEXT REFERENCES packages(id),
    reported_views INTEGER NOT NULL CHECK(reported_views >= 0),
    approved_views INTEGER DEFAULT 0 CHECK(approved_views >= 0),
    reward_rate_ksh INTEGER NOT NULL DEFAULT 0,
    reward_amount_ksh INTEGER DEFAULT 0,
    evidence_text TEXT,
    evidence_id TEXT REFERENCES task_evidence(id),
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'approved', 'rejected')),
    admin_notes TEXT,
    reviewed_by TEXT REFERENCES users(id),
    reviewed_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_task_submissions_user_id ON task_submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_task_submissions_status ON task_submissions(status);
CREATE INDEX IF NOT EXISTS idx_task_submissions_created_at ON task_submissions(created_at);

-- 8. Wallets Table (Auditable Balances)
CREATE TABLE IF NOT EXISTS wallets (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    available_balance_ksh INTEGER NOT NULL DEFAULT 0 CHECK(available_balance_ksh >= 0),
    reserved_balance_ksh INTEGER NOT NULL DEFAULT 0 CHECK(reserved_balance_ksh >= 0),
    lifetime_earnings_ksh INTEGER NOT NULL DEFAULT 0 CHECK(lifetime_earnings_ksh >= 0),
    lifetime_withdrawn_ksh INTEGER NOT NULL DEFAULT 0 CHECK(lifetime_withdrawn_ksh >= 0),
    updated_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wallets_user_id ON wallets(user_id);

-- 9. Wallet Transactions Ledger
CREATE TABLE IF NOT EXISTS wallet_transactions (
    id TEXT PRIMARY KEY,
    wallet_id TEXT NOT NULL REFERENCES wallets(id),
    user_id TEXT NOT NULL REFERENCES users(id),
    type TEXT NOT NULL CHECK(type IN ('task_reward', 'withdrawal_reserve', 'withdrawal_complete', 'withdrawal_refund', 'package_purchase', 'adjustment')),
    amount_ksh INTEGER NOT NULL,
    balance_after_ksh INTEGER NOT NULL,
    reference_id TEXT,
    description TEXT NOT NULL,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wallet_tx_user ON wallet_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_wallet_tx_wallet ON wallet_transactions(wallet_id);

-- 10. Withdrawal Requests Table
CREATE TABLE IF NOT EXISTS withdrawal_requests (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    wallet_id TEXT NOT NULL REFERENCES wallets(id),
    amount_ksh INTEGER NOT NULL CHECK(amount_ksh > 0),
    phone_number TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'processing', 'completed', 'rejected')),
    mpesa_receipt_number TEXT,
    rejection_reason TEXT,
    processed_by TEXT REFERENCES users(id),
    processed_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_withdrawal_user ON withdrawal_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_withdrawal_status ON withdrawal_requests(status);

-- 11. Payment Transactions Table (M-Pesa / Package activations)
CREATE TABLE IF NOT EXISTS payment_transactions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id),
    package_id TEXT NOT NULL REFERENCES packages(id),
    amount_ksh INTEGER NOT NULL,
    phone_number TEXT NOT NULL,
    payment_method TEXT NOT NULL DEFAULT 'mpesa',
    mpesa_checkout_id TEXT,
    mpesa_receipt_number TEXT,
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending', 'completed', 'failed')),
    notes TEXT,
    verified_at INTEGER,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_payments_user ON payment_transactions(user_id);
CREATE INDEX IF NOT EXISTS idx_payments_receipt ON payment_transactions(mpesa_receipt_number);

-- 12. Service Inquiries Table (For Brand Advertisers)
CREATE TABLE IF NOT EXISTS service_inquiries (
    id TEXT PRIMARY KEY,
    user_id TEXT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    business_name TEXT,
    service_type TEXT NOT NULL,
    budget_range TEXT,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'new' CHECK(status IN ('new', 'contacted', 'resolved')),
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inquiries_status ON service_inquiries(status);

-- 13. Admin Audit Logs Table
CREATE TABLE IF NOT EXISTS admin_audit_logs (
    id TEXT PRIMARY KEY,
    admin_id TEXT NOT NULL REFERENCES users(id),
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    details TEXT, -- JSON format
    ip_address TEXT,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_admin ON admin_audit_logs(admin_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON admin_audit_logs(created_at);

-- ====================================================================
-- SEED DATA: Packages & Initial Advertising Campaigns
-- ====================================================================

-- Insert Official Packages
INSERT OR REPLACE INTO packages (id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, features, badge, is_active, created_at)
VALUES 
(
    'pkg_starter',
    'Starter Z',
    'starter-z',
    250,
    20,
    50,
    '["KSh 20 per approved view","Pay KSh 250 activation fee","Up to 50 views per 24h task","Direct M-Pesa withdrawals","Standard campaign access"]',
    'Entry Tier',
    1,
    1710000000
),
(
    'pkg_exclusive',
    'Exclusive',
    'exclusive',
    500,
    50,
    100,
    '["KSh 50 per approved view","Pay KSh 500 activation fee","Up to 100 views per 24h task","Priority M-Pesa processing","Priority brand campaign access"]',
    'Most Popular',
    1,
    1710000000
),
(
    'pkg_premium',
    'Premium',
    'premium',
    1200,
    100,
    200,
    '["KSh 100 per approved view","Pay KSh 1,200 activation fee","Up to 200 views per 24h task","VIP instant M-Pesa processing","Executive campaign sponsorships"]',
    'Maximum Earnings',
    1,
    1710000000
);

-- Insert Default Live Advertising Campaign
INSERT OR REPLACE INTO campaigns (id, title, brand_name, description, target_link, guidelines, status, created_at)
VALUES 
(
    'camp_almai_main',
    'Almai Digital Growth & Mobile Brand Blast',
    'Almai Ads Network',
    'Post the official Almai creative banner on your WhatsApp Status. Keep it up for 24 hours to maximize your genuine view count.',
    'https://almai.pages.dev',
    '1. Upload the official banner to your WhatsApp Status. 2. Write caption: "Discover real digital marketing solutions with Almai Ads!". 3. After 24 hours, take an unedited full-screen screenshot showing the view count. 4. Submit screenshot & count here.',
    'active',
    1710000000
);
