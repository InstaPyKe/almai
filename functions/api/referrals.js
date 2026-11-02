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

  try {
    // 1. Ensure user has a unique referral code
    let referralCode = user.referralCode;
    if (!referralCode) {
      const dbUser = await env.DB.prepare('SELECT referral_code FROM users WHERE id = ?').bind(user.id).first();
      referralCode = dbUser?.referral_code;
      if (!referralCode) {
        referralCode = 'ALM' + user.id.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase();
        await env.DB.prepare('UPDATE users SET referral_code = ? WHERE id = ?').bind(referralCode, user.id).run().catch(() => {});
      }
    }

    // 2. Aggregate metrics for downlines
    const summary = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_invited,
        COUNT(CASE WHEN status = 'active_paid' THEN 1 END) as active_paid_count,
        COALESCE(SUM(CASE WHEN status = 'active_paid' THEN commission_amount_ksh ELSE 0 END), 0) as total_earnings_ksh
      FROM referrals
      WHERE referrer_id = ?
    `).bind(user.id).first();

    const totalInvited = summary?.total_invited || 0;
    const activePaidCount = summary?.active_paid_count || 0;
    const totalEarningsKsh = summary?.total_earnings_ksh || 0;

    // 3. Fetch active paid downlines with active packages (45% commission verified)
    const { results: activeReferrals } = await env.DB.prepare(`
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

    // 4. Fetch all downlines for complete partner visibility
    const { results: allReferrals } = await env.DB.prepare(`
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

    return jsonSuccess({
      referralCode,
      commissionRatePercent: 45,
      totalInvited,
      activePaidCount,
      totalEarningsKsh,
      activeReferrals: activeReferrals || [],
      allReferrals: allReferrals || []
    });

  } catch (err) {
    console.error('Referrals API error:', err);
    return jsonError('Failed to retrieve referral data', 500);
  }
}

