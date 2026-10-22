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

    if (task.status !== 'pending') {
      return jsonError(`This task submission has already been ${task.status}.`, 409);
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (action === 'approve') {
      const views = parseInt(approvedViews, 10);
      if (isNaN(views) || views <= 0) {
        return jsonError('Please specify valid approved views greater than 0', 400);
      }

      // Check max allowed views from package if configured
      const maxViews = task.max_views_per_task || 200;
      if (views > maxViews) {
        return jsonError(`Approved views (${views}) exceeds package cap of ${maxViews} views`, 400);
      }

      // Calculate reward: verified views * rate per view
      const rewardKsh = views * task.reward_rate_ksh;

      // 1. Fetch user's current wallet
      const wallet = await env.DB.prepare('SELECT id, available_balance_ksh FROM wallets WHERE user_id = ?').bind(task.user_id).first();
      if (!wallet) {
        return jsonError('User wallet not found', 404);
      }

      const balanceAfter = wallet.available_balance_ksh + rewardKsh;

      // 2. Update task submission
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'approved',
            approved_views = ?,
            reward_amount_ksh = ?,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(views, rewardKsh, notes || 'Verified screenshot evidence', admin.id, now, task.id).run();

      // 3. Atomically credit wallet
      await env.DB.prepare(`
        UPDATE wallets
        SET available_balance_ksh = available_balance_ksh + ?,
            lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(rewardKsh, rewardKsh, now, task.user_id).run();

      // 4. Record wallet transaction
      const txId = generateId('tx');
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        task.user_id,
        rewardKsh,
        balanceAfter,
        task.id,
        `Campaign reward credited: ${views} approved WhatsApp Status views @ KSh ${task.reward_rate_ksh}/view`,
        now
      ).run();

      // 5. Audit log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'APPROVE_TASK',
        targetType: 'task_submission',
        targetId: task.id,
        details: { approvedViews: views, rewardKsh, notes },
        ip
      });

      return jsonSuccess({
        message: `Task submission approved! Credited KSh ${rewardKsh} to partner wallet.`,
        task: {
          id: task.id,
          status: 'approved',
          approvedViews: views,
          rewardAmountKsh: rewardKsh
        }
      });

    } else if (action === 'reject') {
      const reason = notes || 'Screenshot evidence could not be verified or does not match requirements';

      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'rejected',
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(reason, admin.id, now, task.id).run();

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
