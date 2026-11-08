// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/tasks
// Protected Administrator Task Review Endpoint
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

/**
 * GET /api/admin/tasks
 * Retrieve pending and recent submissions for verification
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get('status') || 'pending';

    let query = `
      SELECT ts.id, ts.user_id, ts.campaign_id, ts.package_id, ts.reported_views,
             ts.approved_views, ts.reward_rate_ksh, ts.reward_amount_ksh,
             ts.evidence_text, ts.evidence_id, ts.status, ts.admin_notes,
             ts.created_at, ts.reviewed_at,
             u.name as user_name, u.email as user_email, u.phone as user_phone,
             c.title as campaign_title, p.name as package_name, p.max_views_per_task
      FROM task_submissions ts
      JOIN users u ON ts.user_id = u.id
      LEFT JOIN campaigns c ON ts.campaign_id = c.id
      LEFT JOIN packages p ON ts.package_id = p.id
    `;

    let params = [];
    if (filterStatus === 'pending') {
      query += ` WHERE ts.status = 'pending' ORDER BY ts.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY ts.created_at DESC LIMIT 100`;
    }

    const { results } = await env.DB.prepare(query).all();

    return jsonSuccess({
      submissions: results || []
    });

  } catch (err) {
    console.error('Admin fetch tasks error:', err);
    return jsonError('Failed to fetch submissions for review', 500);
  }
}

/**
 * POST /api/admin/tasks
 * Review task submission: Approve with verified views or Reject
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const admin = auth.user;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const { submissionId, action, approvedViews, notes } = body;

  if (!submissionId || !action) {
    return jsonError('submissionId and action ("approve" | "reject") are required', 400);
  }

  try {
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

    // 1. Fetch task submission
    const task = await env.DB.prepare(`
      SELECT ts.*, p.max_views_per_task
      FROM task_submissions ts
      LEFT JOIN packages p ON ts.package_id = p.id
      WHERE ts.id = ?
      LIMIT 1
    `).bind(submissionId).first();

    if (!task) {
      return jsonError('Task submission not found', 404);
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (action === 'approve' || action === 'modify') {
      const views = parseInt(approvedViews, 10);
      if (isNaN(views) || views < 0) {
        return jsonError('Please specify valid approved views (0 or greater)', 400);
      }

      const rate = task.reward_rate_ksh || 20;
      const newRewardKsh = Math.round(views * rate);
      const previousRewardKsh = task.status === 'approved' ? (task.reward_amount_ksh || 0) : 0;
      const rewardDeltaKsh = newRewardKsh - previousRewardKsh;

      // 1. Ensure user has a wallet
      let wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(task.user_id).first();
      if (!wallet) {
        const walletId = generateId('wal');
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, task.user_id, now).run().catch(() => {});
        wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(task.user_id).first();
      }

      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curViewsBal = ((wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef)
        ? (curAvail - curRef)
        : (wallet?.views_balance_ksh || 0);

      const nextViewsBal = Math.max(0, curViewsBal + rewardDeltaKsh);
      const nextAvailBal = Math.max(0, nextViewsBal + curRef);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + rewardDeltaKsh);

      // 2. Update task submission (also sync reported_views if admin modified views)
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'approved',
            approved_views = ?,
            reported_views = CASE WHEN ? > reported_views THEN ? ELSE reported_views END,
            reward_amount_ksh = ?,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ?
      `).bind(views, views, views, newRewardKsh, notes || 'Verified screenshot evidence', admin.id, now, task.id).run();

      // 3. Atomically update wallet views and available balances
      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextAvailBal, nextLifetime, now, task.user_id).run();

      // 4. Record wallet transaction if reward changed
      if (rewardDeltaKsh !== 0) {
        const txId = generateId('tx');
        await env.DB.prepare(`
          INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
          VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
        `).bind(
          txId,
          wallet.id,
          task.user_id,
          rewardDeltaKsh,
          nextAvailBal,
          task.id,
          `Campaign reward credited: ${views} approved WhatsApp Status views @ KSh ${rate}/view`,
          now
        ).run();
      }

      // 5. Audit log
      await createAuditLog(env, {
        adminId: admin.id,
        action: task.status === 'approved' ? 'MODIFY_APPROVED_TASK' : 'APPROVE_TASK',
        targetType: 'task_submission',
        targetId: task.id,
        details: { approvedViews: views, newRewardKsh, rewardDeltaKsh, notes },
        ip
      });

      return jsonSuccess({
        message: `Task submission ${task.status === 'approved' ? 'updated' : 'approved'}! ${views} views (KSh ${newRewardKsh.toLocaleString()}) credited to partner wallet.`,
        task: {
          id: task.id,
          status: 'approved',
          approvedViews: views,
          rewardAmountKsh: newRewardKsh
        }
      });

    } else if (action === 'reject') {
      if (task.status === 'rejected') {
        return jsonError('This task submission is already rejected.', 409);
      }
      const reason = notes || 'Screenshot evidence could not be verified or does not match requirements';
      const previousRewardKsh = task.status === 'approved' ? (task.reward_amount_ksh || 0) : 0;

      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'rejected',
            approved_views = 0,
            reward_amount_ksh = 0,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ?
      `).bind(reason, admin.id, now, task.id).run();

      if (previousRewardKsh > 0) {
        await env.DB.prepare(`
          UPDATE wallets
          SET views_balance_ksh = MAX(0, COALESCE(views_balance_ksh, 0) - ?),
              available_balance_ksh = MAX(0, COALESCE(available_balance_ksh, 0) - ?),
              lifetime_earnings_ksh = MAX(0, COALESCE(lifetime_earnings_ksh, 0) - ?),
              updated_at = ?
          WHERE user_id = ?
        `).bind(previousRewardKsh, previousRewardKsh, previousRewardKsh, now, task.user_id).run();
      }

      // Audit log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'REJECT_TASK',
        targetType: 'task_submission',
        targetId: task.id,
        details: { reason },
        ip
      });

      return jsonSuccess({
        message: 'Task submission has been rejected.',
        task: {
          id: task.id,
          status: 'rejected',
          reason
        }
      });

    } else {
      return jsonError('Invalid action specified. Must be "approve" or "reject".', 400);
    }

  } catch (err) {
    console.error('Admin review error:', err);
    return jsonError('Failed to process task review. Please try again.', 500);
  }
}
