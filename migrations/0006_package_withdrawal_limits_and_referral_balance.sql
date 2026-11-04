-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0006
-- Unique Package Withdrawal Limits (Views Only) & Separate Referral Withdrawals
-- ====================================================================

-- 1. Add min_withdrawal_views_ksh to packages table
ALTER TABLE packages ADD COLUMN min_withdrawal_views_ksh INTEGER NOT NULL DEFAULT 5000;

-- 2. Set unique withdrawal limits per package (lowest = 5000 for views)
UPDATE packages SET min_withdrawal_views_ksh = 5000 WHERE id = 'pkg_starter';
UPDATE packages SET min_withdrawal_views_ksh = 8000 WHERE id = 'pkg_exclusive';
UPDATE packages SET min_withdrawal_views_ksh = 12000 WHERE id = 'pkg_premium';

-- 3. Add views_balance_ksh and referrals_balance_ksh to wallets table
ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0;
ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0;

-- 4. Add balance_type to withdrawal_requests table
ALTER TABLE withdrawal_requests ADD COLUMN balance_type TEXT NOT NULL DEFAULT 'views';

-- 5. Backfill existing wallet balances:
-- Allocate existing referral earnings to referrals_balance_ksh, remainder to views_balance_ksh
UPDATE wallets 
SET referrals_balance_ksh = COALESCE((
    SELECT SUM(commission_amount_ksh) 
    FROM referrals 
    WHERE referrals.referrer_id = wallets.user_id 
      AND referrals.status = 'active_paid' 
      AND referrals.commission_paid = 1
), 0);

UPDATE wallets 
SET referrals_balance_ksh = MIN(available_balance_ksh, referrals_balance_ksh);

UPDATE wallets 
SET views_balance_ksh = MAX(0, available_balance_ksh - referrals_balance_ksh);
