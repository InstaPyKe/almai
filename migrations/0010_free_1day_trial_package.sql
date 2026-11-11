-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0010
-- Flexible Free 1-Day Trial Package & Package Duration Support
-- Paid plans (Starter Pro, Exclusive, Premium) remain untouched with NULL duration.
-- ====================================================================

ALTER TABLE packages ADD COLUMN duration_hours INTEGER DEFAULT NULL;
ALTER TABLE packages ADD COLUMN is_free_trial INTEGER NOT NULL DEFAULT 0;

INSERT OR IGNORE INTO packages (
  id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task,
  min_withdrawal_views_ksh, features, badge, is_active, created_at,
  duration_hours, is_free_trial
) VALUES (
  'pkg_free_trial',
  '1-Day Free Trial',
  'free-trial',
  0,
  15,
  25,
  5000,
  '["Free 24-hour full partner access","Earn KSh 15 per approved view","Up to 25 views per WhatsApp task","Full Paid Surveys & Creative access","Upgrade anytime to keep earning permanently"]',
  'FREE 1-DAY TRIAL',
  1,
  unixepoch(),
  24,
  1
);

