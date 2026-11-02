-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0004
-- Update Administrator Credentials & Role Enforcement
-- ====================================================================

-- 1. Demote any non-whitelisted administrators and remove legacy credentials
UPDATE users SET role = 'user' WHERE email != 'mentorbravin@gmail.com' AND role = 'admin';
DELETE FROM users WHERE email = 'almai@admin.co.ke';
DELETE FROM wallets WHERE id = 'wal_admin_almai';

-- 2. Ensure official administrator account
-- Email: mentorbravin@gmail.com
-- Password: Mentor@2026
-- Salt: b7e2c9d1a4f50827364b5c6d7e8f9102
-- Hash: a1194e448c3ef0848f7884c1b3475daa750717a16d591efb0121cf442b5bee7e
INSERT INTO users (
    id, name, email, phone, password_hash, salt, role, status, created_at, updated_at
) VALUES (
    'usr_admin_mentorbravin',
    'Bravin Mentor (Admin)',
    'mentorbravin@gmail.com',
    '0700000000',
    'a1194e448c3ef0848f7884c1b3475daa750717a16d591efb0121cf442b5bee7e',
    'b7e2c9d1a4f50827364b5c6d7e8f9102',
    'admin',
    'active',
    strftime('%s', 'now'),
    strftime('%s', 'now')
)
ON CONFLICT(id) DO UPDATE SET
    role = 'admin',
    password_hash = 'a1194e448c3ef0848f7884c1b3475daa750717a16d591efb0121cf442b5bee7e',
    salt = 'b7e2c9d1a4f50827364b5c6d7e8f9102',
    status = 'active',
    updated_at = strftime('%s', 'now');

INSERT OR IGNORE INTO wallets (
    id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at
) VALUES (
    'wal_admin_mentorbravin',
    'usr_admin_mentorbravin',
    0, 0, 0, 0,
    strftime('%s', 'now')
);

