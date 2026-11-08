// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/users
// Protected Administrator User Directory & Account Management
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId, awardReferralCommission } from '../_utils.js';

/**
 * GET /api/admin/users
 * Search and retrieve users with financial & package profiles
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    // Ensure defensive schema for submission tickets
    await env.DB.prepare("ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

    const url = new URL(request.url);
    const search = url.searchParams.get('q') || '';

    let query = `
      SELECT 
        u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
        COALESCE(u.submission_tickets, 0) as submission_tickets,
        COALESCE(w.available_balance_ksh, 0) as available_balance_ksh,
        COALESCE(w.reserved_balance_ksh, 0) as reserved_balance_ksh,
        COALESCE(w.lifetime_earnings_ksh, 0) as lifetime_earnings_ksh,
        COALESCE(w.lifetime_withdrawn_ksh, 0) as lifetime_withdrawn_ksh,
        p.id as active_package_id,
        p.name as active_package_name,
        p.slug as active_package_slug,
        p.reward_per_view_ksh as active_package_rate,
        up.activated_at as package_activated_at,
        (
          SELECT p_pen.name 
          FROM user_packages up_pen 
          JOIN packages p_pen ON up_pen.package_id = p_pen.id 
          WHERE up_pen.user_id = u.id AND up_pen.status = 'pending_verification' 
          LIMIT 1
        ) as pending_package_name
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      LEFT JOIN user_packages up ON u.id = up.user_id AND up.status = 'active'
      LEFT JOIN packages p ON up.package_id = p.id
    `;

    const params = [];
    if (search.trim()) {
      const term = `%${search.trim().toLowerCase()}%`;
      query += ` WHERE LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ? OR u.phone LIKE ?`;
      params.push(term, term, term);
    }

    query += ` ORDER BY u.created_at DESC LIMIT 150`;

    const stmt = params.length > 0 
      ? env.DB.prepare(query).bind(...params) 
      : env.DB.prepare(query);

    const { results } = await stmt.all();

    return jsonSuccess({
      users: results || []
    });

  } catch (err) {
    console.error('Admin fetch users error:', err);
    return jsonError('Failed to fetch user directory', 500);
  }
}

/**
 * POST /api/admin/users
 * Manage user roles, statuses, and assign partner packages
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

  const targetUserId = body.targetUserId || body.userId;
  const { action, packageId, newStatus, newRole } = body;

  if (!targetUserId || !action) {
    return jsonError('targetUserId and action are required', 400);
  }

  try {
    // Ensure defensive schema for submission tickets and wallet columns
    await env.DB.prepare("ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    // 1. Fetch target user
    const target = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(targetUserId).first();
    if (!target) {
      return jsonError('Target user not found', 404);
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (action === 'assign_package') {
      if (!packageId) {
        return jsonError('packageId is required to assign package', 400);
      }

      const pkg = await env.DB.prepare('SELECT * FROM packages WHERE id = ?').bind(packageId).first();
      if (!pkg) {
        return jsonError('Selected package was not found', 404);
      }

      // Expire previous active packages
      await env.DB.prepare("UPDATE user_packages SET status = 'expired' WHERE user_id = ? AND status = 'active'").bind(target.id).run();

      // Clean up any pending
      await env.DB.prepare("DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'").bind(target.id).run();

      // Insert new active package
      const userPackageId = generateId('upkg');
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'active', ?)
      `).bind(userPackageId, target.id, pkg.id, now).run();

      // Award 45% Referral Commission to verified referrer
      await awardReferralCommission(env, target.id, pkg.id, pkg.name, pkg.price_ksh);

      // Audit log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'ADMIN_ASSIGN_PACKAGE',
        targetType: 'user',
        targetId: target.id,
        details: { packageId: pkg.id, packageName: pkg.name, assignedTo: target.email },
        ip
      });

      return jsonSuccess({
        message: `Package ${pkg.name} manually activated for ${target.name} (${target.email})!`,
        package: pkg
      });

    } else if (action === 'toggle_status') {
      const nextStatus = newStatus || (target.status === 'active' ? 'suspended' : 'active');

      await env.DB.prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?')
        .bind(nextStatus, now, target.id).run();

      // If suspended, revoke active sessions
      if (nextStatus === 'suspended') {
        await env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(target.id).run();
      }

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'TOGGLE_USER_STATUS',
        targetType: 'user',
        targetId: target.id,
        details: { oldStatus: target.status, newStatus: nextStatus },
        ip
      });

      return jsonSuccess({
        message: `User ${target.name} status updated to ${nextStatus}.`,
        status: nextStatus
      });

    } else if (action === 'toggle_role') {
      const nextRole = newRole || (target.role === 'admin' ? 'user' : 'admin');
      if (nextRole === 'admin' && target.email.toLowerCase() !== 'mentorbravin@gmail.com') {
        return jsonError('Only mentorbravin@gmail.com can hold the Administrator role.', 400);
      }
      if (target.email.toLowerCase() === 'mentorbravin@gmail.com' && nextRole !== 'admin') {
        return jsonError('Primary administrator account cannot be demoted.', 400);
      }

      await env.DB.prepare('UPDATE users SET role = ?, updated_at = ? WHERE id = ?')
        .bind(nextRole, now, target.id).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'TOGGLE_USER_ROLE',
        targetType: 'user',
        targetId: target.id,
        details: { oldRole: target.role, newRole: nextRole },
        ip
      });

      return jsonSuccess({
        message: `User ${target.name} role updated to ${nextRole}.`,
        role: nextRole
      });

    } else if (action === 'modify_views') {
      const views = parseInt(body.views || body.viewsDelta || 0, 10);
      if (isNaN(views) || views === 0) {
        return jsonError('Please specify a valid non-zero views adjustment count (e.g. 50 or -20)', 400);
      }

      // Determine rate: provided in request, or user's active package rate, or default 20
      let rate = body.rate ? parseFloat(body.rate) : null;
      if (!rate || isNaN(rate) || rate <= 0) {
        const activePkg = await env.DB.prepare(`
          SELECT p.reward_per_view_ksh, p.id as package_id
          FROM user_packages up
          JOIN packages p ON up.package_id = p.id
          WHERE up.user_id = ? AND up.status = 'active'
          ORDER BY up.activated_at DESC
          LIMIT 1
        `).bind(target.id).first();

        rate = activePkg ? activePkg.reward_per_view_ksh : 20;
      }

      const rewardKsh = Math.round(views * rate);
      const note = (body.note || body.reason || 'Admin views modification').trim();

      // Ensure user has a wallet
      let wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      if (!wallet) {
        const walletId = generateId('wal');
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, created_at, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?, ?)
        `).bind(walletId, target.id, now, now).run().catch(() => {});
        wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      }

      // Atomically update wallet balances
      if (rewardKsh >= 0) {
        await env.DB.prepare(`
          UPDATE wallets
          SET views_balance_ksh = COALESCE(views_balance_ksh, 0) + ?,
              available_balance_ksh = COALESCE(available_balance_ksh, 0) + ?,
              lifetime_earnings_ksh = COALESCE(lifetime_earnings_ksh, 0) + ?,
              updated_at = ?
          WHERE user_id = ?
        `).bind(rewardKsh, rewardKsh, rewardKsh, now, target.id).run();
      } else {
        const deduction = Math.abs(rewardKsh);
        await env.DB.prepare(`
          UPDATE wallets
          SET views_balance_ksh = MAX(0, COALESCE(views_balance_ksh, 0) - ?),
              available_balance_ksh = MAX(0, COALESCE(available_balance_ksh, 0) - ?),
              updated_at = ?
          WHERE user_id = ?
        `).bind(deduction, deduction, now, target.id).run();
      }

      // Record in task_submissions so user history and metrics reflect the verified views
      const activePkgRow = await env.DB.prepare(`
        SELECT package_id FROM user_packages WHERE user_id = ? AND status = 'active' ORDER BY activated_at DESC LIMIT 1
      `).bind(target.id).first();
      const pkgId = activePkgRow ? activePkgRow.package_id : 'pkg_starter';
      const taskId = generateId('tsk_adm');

      await env.DB.prepare(`
        INSERT INTO task_submissions (
          id, user_id, campaign_id, package_id, reported_views, approved_views,
          reward_rate_ksh, reward_amount_ksh, evidence_text, status,
          admin_notes, reviewed_by, reviewed_at, created_at
        )
        VALUES (?, ?, 'camp_admin_credit', ?, ?, ?, ?, ?, ?, 'approved', ?, ?, ?, ?)
      `).bind(
        taskId,
        target.id,
        pkgId,
        views,
        views,
        rate,
        rewardKsh,
        `Admin views modification: ${views >= 0 ? '+' : ''}${views} views`,
        note,
        admin.id,
        now,
        now
      ).run();

      // Record wallet transaction
      const txId = generateId('tx');
      const updatedWallet = await env.DB.prepare('SELECT available_balance_ksh, views_balance_ksh FROM wallets WHERE user_id = ?').bind(target.id).first();
      const balanceAfter = updatedWallet ? updatedWallet.available_balance_ksh : 0;

      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        target.id,
        rewardKsh,
        balanceAfter,
        taskId,
        `Admin views adjustment: ${views >= 0 ? '+' : ''}${views} views @ KSh ${rate}/view (${note})`,
        now
      ).run();

      // Audit log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'ADMIN_MODIFY_VIEWS',
        targetType: 'user',
        targetId: target.id,
        details: { views, rate, rewardKsh, note, userEmail: target.email },
        ip
      });

      return jsonSuccess({
        message: `Successfully adjusted ${views >= 0 ? '+' : ''}${views} views (KSh ${rewardKsh.toLocaleString()}) for ${target.name}!`,
        views,
        rate,
        rewardKsh,
        availableBalanceKsh: balanceAfter
      });

    } else if (action === 'grant_submission_ticket') {
      const tickets = parseInt(body.tickets || body.count || 1, 10);
      if (isNaN(tickets) || tickets <= 0) {
        return jsonError('Please enter a valid positive number of submission tickets to grant', 400);
      }

      const note = (body.note || body.reason || '18-hour rule waiver ticket').trim();

      await env.DB.prepare(`
        UPDATE users
        SET submission_tickets = COALESCE(submission_tickets, 0) + ?,
            updated_at = ?
        WHERE id = ?
      `).bind(tickets, now, target.id).run();

      const updatedUser = await env.DB.prepare('SELECT submission_tickets FROM users WHERE id = ?').bind(target.id).first();
      const totalTickets = updatedUser ? updatedUser.submission_tickets : tickets;

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'ADMIN_GRANT_SUBMISSION_TICKET',
        targetType: 'user',
        targetId: target.id,
        details: { ticketsGranted: tickets, totalTickets, note, userEmail: target.email },
        ip
      });

      return jsonSuccess({
        message: `Granted ${tickets} submission ticket(s) to ${target.name}. Total tickets: ${totalTickets}. The user can now bypass the 18-hour cooldown rule!`,
        ticketsGranted: tickets,
        totalTickets
      });

    } else {
      return jsonError('Invalid action specified', 400);
    }

  } catch (err) {
    console.error('Admin user action error:', err);
    return jsonError('Failed to perform user administrative action', 500);
  }
}
