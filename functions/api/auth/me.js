// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/auth/me
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, syncAndGetUserPackageState } from '../_utils.js';

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
        SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      try {
        const legacyWallet = await env.DB.prepare(`
          SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
          FROM wallets
          WHERE user_id = ?
          LIMIT 1
        `).bind(user.id).first();
        if (legacyWallet) {
          wallet = {
            ...legacyWallet,
            surveys_balance_ksh: 0
          };
        }
      } catch (e2) { }
    }

    if (!wallet) {
      wallet = {
        available_balance_ksh: 0,
        views_balance_ksh: 0,
        referrals_balance_ksh: 0,
        surveys_balance_ksh: 0,
        reserved_balance_ksh: 0,
        lifetime_earnings_ksh: 0,
        lifetime_withdrawn_ksh: 0
      };
    } else {
      const refBal = Number(wallet.referrals_balance_ksh || 0);
      const surveysBal = Number(wallet.surveys_balance_ksh || 0);
      let viewsBal = Number(wallet.views_balance_ksh || 0);
      let availBal = Number(wallet.available_balance_ksh || 0);
      if (viewsBal === 0 && refBal === 0 && surveysBal === 0 && availBal > 0) {
        viewsBal = availBal;
      } else if (availBal !== viewsBal + refBal + surveysBal) {
        availBal = viewsBal + refBal + surveysBal;
      }
      wallet.views_balance_ksh = viewsBal;
      wallet.referrals_balance_ksh = refBal;
      wallet.surveys_balance_ksh = surveysBal;
      wallet.available_balance_ksh = availBal;
    }

    // 2. Sync expirations & fetch active, pending, and expired-trial package state
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    const {
      activePackage,
      pendingPackage,
      expiredTrialPackage,
      isTrialActive,
      trialExpiresAt,
      trialSecondsRemaining,
      hasUsedFreeTrial,
      isTrialExpiredLockout
    } = pkgState;

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

    // 5. Counts: surveys completed
    const surveyStats = await env.DB.prepare(`
      SELECT COUNT(*) as completed_count, COALESCE(SUM(reward_amount_ksh), 0) as total_earned_ksh
      FROM survey_responses
      WHERE user_id = ?
    `).bind(user.id).first().catch(() => null);

    // 6. Recent regulated active user bonuses received
    let recentBonuses = [];
    try {
      const { results: bonusRows } = await env.DB.prepare(`
        SELECT br.id, br.amount_ksh, br.balance_type, br.created_at, bd.campaign_title
        FROM bonus_recipient_logs br
        JOIN bonus_distributions bd ON br.distribution_id = bd.id
        WHERE br.user_id = ?
        ORDER BY br.created_at DESC
        LIMIT 3
      `).bind(user.id).all();
      recentBonuses = bonusRows || [];
    } catch (_) {
      recentBonuses = [];
    }

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
      expiredTrialPackage: expiredTrialPackage || null,
      hasActivePackage: Boolean(activePackage),
      isTrialActive,
      trialExpiresAt,
      trialSecondsRemaining,
      hasUsedFreeTrial,
      isTrialExpiredLockout,
      recentBonuses,
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
        surveysBalanceKsh: wallet.surveys_balance_ksh || 0,
        completedSurveysCount: surveyStats?.completed_count || 0,
        totalSurveyEarningsKsh: surveyStats?.total_earned_ksh || 0,
        reservedBalanceKsh: wallet.reserved_balance_ksh,
        completedWithdrawalsKsh: wallet.lifetime_withdrawn_ksh
      }
    });

  } catch (err) {
    console.error('/api/auth/me error:', err);
    return jsonError('Failed to retrieve user profile', 500);
  }
}
