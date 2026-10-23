// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/admin/stats
// Protected Administrator System Overview & Metrics
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    // 1. Total users
    const usersCount = await env.DB.prepare('SELECT COUNT(*) as count FROM users').first();

    // 2. Pending reviews
    const pendingTasks = await env.DB.prepare("SELECT COUNT(*) as count FROM task_submissions WHERE status = 'pending'").first();

    // 3. Pending withdrawals
    const pendingWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'pending'").first();

    // 4. Completed withdrawals / disbursements
    const completedWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'completed'").first();

    // 5. Total approved views & total rewards generated
    const taskAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(approved_views), 0) as total_approved_views,
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(reward_amount_ksh), 0) as total_rewards_granted_ksh
      FROM task_submissions
      WHERE status = 'approved'
    `).first();

    // 6. Wallets summary
    const walletAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(available_balance_ksh), 0) as total_available_in_system,
        COALESCE(SUM(reserved_balance_ksh), 0) as total_reserved_in_system
      FROM wallets
    `).first();

    // 7. Pending payment verification codes
    const pendingPayments = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM payment_transactions WHERE status = 'pending'").first();

    // 8. Products count
    const productsCount = await env.DB.prepare("SELECT COUNT(*) as count FROM product_posts WHERE status = 'active'").first();

    return jsonSuccess({
      metrics: {
        totalUsers: usersCount?.count || 0,
        pendingPaymentsCount: pendingPayments?.count || 0,
        pendingPaymentsAmountKsh: pendingPayments?.total_amount || 0,
        totalProductsCount: productsCount?.count || 0,
        pendingTasksCount: pendingTasks?.count || 0,
        pendingWithdrawalsCount: pendingWithdrawals?.count || 0,
        pendingWithdrawalsAmountKsh: pendingWithdrawals?.total_amount || 0,
        completedWithdrawalsCount: completedWithdrawals?.count || 0,
        totalDisbursedKsh: completedWithdrawals?.total_amount || 0,
        totalApprovedViews: taskAggregates?.total_approved_views || 0,
        totalReportedViews: taskAggregates?.total_reported_views || 0,
        totalRewardsGrantedKsh: taskAggregates?.total_rewards_granted_ksh || 0,
        totalAvailableInSystemKsh: walletAggregates?.total_available_in_system || 0,
        totalReservedInSystemKsh: walletAggregates?.total_reserved_in_system || 0
      }
    });

  } catch (err) {
    console.error('Admin stats error:', err);
    return jsonError('Failed to fetch system metrics', 500);
  }
}
