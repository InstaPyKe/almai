// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/auth/me
// ====================================================================

import { jsonError, jsonSuccess, requireAuth } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  try {
    // 1. Fetch wallet data (defensive)
    let wallet = null;
    try {
      wallet = await env.DB.prepare(`
        SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      try {
        const legacyWallet = await env.DB.prepare(`
          SELECT available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
          FROM wallets
          WHERE user_id = ?
          LIMIT 1
        `).bind(user.id).first();
        if (legacyWallet) {
          wallet = {
            ...legacyWallet,
            views_balance_ksh: legacyWallet.available_balance_ksh || 0,
            referrals_balance_ksh: 0
          };
        }
      } catch (e2) {}
    }

    if (!wallet) {
      wallet = {
        available_balance_ksh: 0,
        views_balance_ksh: 0,
        referrals_balance_ksh: 0,
        reserved_balance_ksh: 0,
        lifetime_earnings_ksh: 0,
        lifetime_withdrawn_ksh: 0
      };
    } else {
      const refBal = Number(wallet.referrals_balance_ksh || 0);
      let viewsBal = Number(wallet.views_balance_ksh || 0);
      let availBal = Number(wallet.available_balance_ksh || 0);
      if (viewsBal === 0 && refBal === 0 && availBal > 0) {
        viewsBal = availBal;
      } else if (availBal !== viewsBal + refBal) {
        availBal = viewsBal + refBal;
      }
      wallet.views_balance_ksh = viewsBal;
      wallet.referrals_balance_ksh = refBal;
      wallet.available_balance_ksh = availBal;
    }

    // 2. Fetch active and pending user packages
    const activePackage = await env.DB.prepare(`
      SELECT up.id as user_package_id, up.status, up.activated_at,
             p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.max_views_per_task, p.min_withdrawal_views_ksh, p.badge
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      WHERE up.user_id = ? AND up.status = 'active'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();

    const pendingPackage = await env.DB.prepare(`
      SELECT up.id as user_package_id, up.status, up.activated_at,
             p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.max_views_per_task, p.badge,
             pt.mpesa_receipt_number, pt.created_at as payment_submitted_at
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      LEFT JOIN payment_transactions pt ON pt.user_id = up.user_id AND pt.package_id = up.package_id AND pt.status = 'pending'
      WHERE up.user_id = ? AND up.status = 'pending_verification'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();

    // 3. Check 18h task submission cooldown & tickets (only count user screenshot submissions, not admin credits)
    const userRow = await env.DB.prepare('SELECT COALESCE(submission_tickets, 0) as submission_tickets FROM users WHERE id = ?').bind(user.id).first().catch(() => null);
    const submissionTickets = userRow ? (userRow.submission_tickets || 0) : 0;

    const latestTask = await env.DB.prepare(`
      SELECT created_at, status
      FROM task_submissions
      WHERE user_id = ? AND evidence_id IS NOT NULL
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(user.id).first();

    const now = Math.floor(Date.now() / 1000);
    let canSubmitTask = true;
    let nextSubmissionAllowedAt = now;
    let secondsRemaining = 0;
    let waivedByTicket = false;

    if (latestTask) {
      const cooldownPeriod = 18 * 60 * 60; // 18 hours
      const nextTime = latestTask.created_at + cooldownPeriod;
      if (now < nextTime) {
        secondsRemaining = nextTime - now;
        nextSubmissionAllowedAt = nextTime;
        if (submissionTickets > 0) {
          canSubmitTask = true;
          waivedByTicket = true;
        } else {
          canSubmitTask = false;
        }
      }
    }

    // 4. Counts: reported, pending, approved views & rewards
    const taskStats = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(CASE WHEN status = 'pending' THEN reported_views ELSE 0 END), 0) as pending_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN approved_views ELSE 0 END), 0) as approved_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN reward_amount_ksh ELSE 0 END), 0) as total_approved_rewards_ksh,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks_count
      FROM task_submissions
      WHERE user_id = ?
    `).bind(user.id).first();

    return jsonSuccess({
      authenticated: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        referralCode: user.referralCode,
        submissionTickets
      },
      wallet,
      activePackage: activePackage || null,
      pendingPackage: pendingPackage || null,
      hasActivePackage: Boolean(activePackage),
      cooldown: {
        canSubmitTask,
        nextSubmissionAllowedAt,
        secondsRemaining,
        lastSubmittedAt: latestTask ? latestTask.created_at : null,
        waivedByTicket,
        submissionTickets
      },
      stats: {
        reportedViews: taskStats?.total_reported_views || 0,
        pendingViews: taskStats?.pending_views || 0,
        approvedViews: taskStats?.approved_views || 0,
        approvedRewardsKsh: taskStats?.total_approved_rewards_ksh || 0,
        pendingTasksCount: taskStats?.pending_tasks_count || 0,
        availableBalanceKsh: wallet.available_balance_ksh,
        viewsBalanceKsh: wallet.views_balance_ksh || 0,
        referralsBalanceKsh: wallet.referrals_balance_ksh || 0,
        reservedBalanceKsh: wallet.reserved_balance_ksh,
        completedWithdrawalsKsh: wallet.lifetime_withdrawn_ksh
      }
    });

  } catch (err) {
    console.error('/api/auth/me error:', err);
    return jsonError('Failed to retrieve user profile', 500);
  }
}
