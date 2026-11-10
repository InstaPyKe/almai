// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/referrals
// 45% Referral Downlines & Earnings Engine
// ====================================================================

import { jsonError, jsonSuccess, requireAuth } from './_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  // 1. Guaranteed unique referral code
  let referralCode = user.referralCode;
  if (!referralCode) {
    try {
      const dbUser = await env.DB.prepare('SELECT referral_code FROM users WHERE id = ?').bind(user.id).first();
      referralCode = dbUser?.referral_code;
    } catch (e) {
      console.warn('Failed to query user referral_code:', e);
    }

    if (!referralCode) {
      referralCode = 'ALM' + user.id.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase();
      try {
        await env.DB.prepare('UPDATE users SET referral_code = ? WHERE id = ?').bind(referralCode, user.id).run();
      } catch (e) {
        console.warn('Failed to persist user referral_code:', e);
      }
    }
  }

  // 2. Aggregate downlines metrics (defensive)
  let totalInvited = 0;
  let activePaidCount = 0;
  let totalEarningsKsh = 0;

  try {
    const summary = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_invited,
        COUNT(CASE WHEN status = 'active_paid' THEN 1 END) as active_paid_count,
        COALESCE(SUM(CASE WHEN status = 'active_paid' THEN commission_amount_ksh ELSE 0 END), 0) as total_earnings_ksh
      FROM referrals
      WHERE referrer_id = ?
    `).bind(user.id).first();

    if (summary) {
      totalInvited = summary.total_invited || 0;
      activePaidCount = summary.active_paid_count || 0;
      totalEarningsKsh = summary.total_earnings_ksh || 0;
    }
  } catch (err) {
    console.warn('Referrals summary query fallback:', err);
  }

  // 3. Active paid downlines (defensive)
  let activeReferrals = [];
  try {
    const activeRows = await env.DB.prepare(`
      SELECT 
        r.id,
        r.referred_user_id,
        u.name as downline_name,
        u.phone as downline_phone,
        u.email as downline_email,
        r.status,
        r.package_id,
        r.package_name,
        r.package_price_ksh,
        r.commission_rate,
        r.commission_amount_ksh,
        r.created_at,
        r.activated_at
      FROM referrals r
      JOIN users u ON r.referred_user_id = u.id
      WHERE r.referrer_id = ? AND r.status = 'active_paid'
      ORDER BY r.activated_at DESC
      LIMIT 100
    `).bind(user.id).all();

    activeReferrals = activeRows?.results || [];
  } catch (err) {
    console.warn('Active referrals query fallback:', err);
  }

  // 4. All downlines (defensive)
  let allReferrals = [];
  try {
    const allRows = await env.DB.prepare(`
      SELECT 
        r.id,
        r.referred_user_id,
        u.name as downline_name,
        u.phone as downline_phone,
        r.status,
        r.package_name,
        r.package_price_ksh,
        r.commission_amount_ksh,
        r.created_at,
        r.activated_at
      FROM referrals r
      JOIN users u ON r.referred_user_id = u.id
      WHERE r.referrer_id = ?
      ORDER BY (CASE WHEN r.status = 'active_paid' THEN 0 ELSE 1 END), r.created_at DESC
      LIMIT 100
    `).bind(user.id).all();

    allReferrals = allRows?.results || [];
  } catch (err) {
    console.warn('All referrals query fallback:', err);
  }

  // 5. Withdrawable balance (defensive against missing column)
  let withdrawableReferralsKsh = 0;
  try {
    const wal = await env.DB.prepare('SELECT referrals_balance_ksh FROM wallets WHERE user_id = ?').bind(user.id).first();
    withdrawableReferralsKsh = wal?.referrals_balance_ksh || 0;
  } catch (err) {
    withdrawableReferralsKsh = totalEarningsKsh;
  }

  return jsonSuccess({
    referralCode,
    commissionRatePercent: 45,
    totalInvited,
    activePaidCount,
    totalEarningsKsh,
    withdrawableReferralsKsh,
    minWithdrawalReferralsKsh: 1200,
    activeReferrals: activeReferrals || [],
    allReferrals: allReferrals || []
  });
}
