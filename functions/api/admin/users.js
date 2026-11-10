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
    // Ensure defensive schema for submission tickets and wallet sub-balances
    await env.DB.prepare("ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

    const url = new URL(request.url);
    const search = url.searchParams.get('q') || '';

    let query = `
      SELECT 
        u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
        COALESCE(u.submission_tickets, 0) as submission_tickets,
        COALESCE(w.available_balance_ksh, 0) as available_balance_ksh,
        COALESCE(w.views_balance_ksh, 0) as views_balance_ksh,
        COALESCE(w.referrals_balance_ksh, 0) as referrals_balance_ksh,
        COALESCE(w.surveys_balance_ksh, 0) as surveys_balance_ksh,
        COALESCE(w.reserved_balance_ksh, 0) as reserved_balance_ksh,
        COALESCE(w.lifetime_earnings_ksh, 0) as lifetime_earnings_ksh,
        COALESCE(w.lifetime_withdrawn_ksh, 0) as lifetime_withdrawn_ksh,
        (
          SELECT COALESCE(SUM(ts.reported_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id
        ) as total_reported_views,
        (
          SELECT COALESCE(SUM(ts.approved_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id AND ts.status = 'approved'
        ) as total_approved_views,
        (
          SELECT COALESCE(SUM(ts.reported_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id AND ts.status = 'pending'
        ) as pending_views,
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

      // Support either delta views (e.g. 50, -20) or exact target views (mode === 'set' or '=100')
      const curViewsRow = await env.DB.prepare(`
        SELECT COALESCE(SUM(CASE WHEN status = 'approved' THEN approved_views ELSE 0 END), 0) as approved_views
        FROM task_submissions
        WHERE user_id = ?
      `).bind(target.id).first();
      const currentApprovedViews = curViewsRow ? (curViewsRow.approved_views || 0) : 0;

      const rawViewsStr = String(body.views ?? body.viewsDelta ?? '').trim();
      let views = 0;
      if (body.mode === 'set' || rawViewsStr.startsWith('=')) {
        const targetTotalViews = parseInt(rawViewsStr.replace(/^=/, ''), 10);
        if (isNaN(targetTotalViews) || targetTotalViews < 0) {
          return jsonError('Please specify a valid non-negative target views count', 400);
        }
        views = targetTotalViews - currentApprovedViews;
      } else {
        views = parseInt(rawViewsStr, 10);
      }

      if (isNaN(views) || views === 0) {
        return jsonError('Please specify a valid non-zero views adjustment count (e.g. 50, -20, or =100)', 400);
      }

      const rewardKsh = Math.round(views * rate);
      const note = (body.note || body.reason || 'Admin views modification').trim();

      // Ensure user has a wallet (note: wallets table does NOT have created_at column)
      let wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      if (!wallet) {
        const walletId = generateId('wal');
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, target.id, now).run().catch(() => {});
        wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      }

      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curViewsBal = ((wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef)
        ? (curAvail - curRef)
        : (wallet?.views_balance_ksh || 0);

      const nextViewsBal = Math.max(0, curViewsBal + rewardKsh);
      const nextAvailBal = Math.max(0, nextViewsBal + curRef);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + rewardKsh);

      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextAvailBal, nextLifetime, now, target.id).run();

      const taskId = generateId('tsk_adm');

      if (views > 0) {
        // Insert positive approved views record with NULL campaign_id & evidence_id so FK and 18h cooldown are respected
        const activePkgRow = await env.DB.prepare(`
          SELECT up.package_id FROM user_packages up JOIN packages p ON up.package_id = p.id WHERE up.user_id = ? AND up.status = 'active' ORDER BY up.activated_at DESC LIMIT 1
        `).bind(target.id).first();
        const pkgId = activePkgRow ? activePkgRow.package_id : null;

        await env.DB.prepare(`
          INSERT INTO task_submissions (
            id, user_id, campaign_id, package_id, reported_views, approved_views,
            reward_rate_ksh, reward_amount_ksh, evidence_text, evidence_id, status,
            admin_notes, reviewed_by, reviewed_at, created_at
          )
          VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, 'approved', ?, ?, ?, ?)
        `).bind(
          taskId,
          target.id,
          pkgId,
          views,
          views,
          rate,
          rewardKsh,
          `Admin views credit: +${views} views @ KSh ${rate}/view`,
          note,
          admin.id,
          now,
          now
        ).run();
      } else {
        // Deduct views safely across existing task_submissions (respecting CHECK(reported_views >= 0) and CHECK(approved_views >= 0))
        let remainingToDeduct = Math.abs(views);
        const { results: existingTasks } = await env.DB.prepare(`
          SELECT id, reported_views, approved_views, reward_rate_ksh, reward_amount_ksh
          FROM task_submissions
          WHERE user_id = ? AND (approved_views > 0 OR reported_views > 0)
          ORDER BY created_at DESC
        `).bind(target.id).all();

        for (const t of (existingTasks || [])) {
          if (remainingToDeduct <= 0) break;
          const curApp = t.approved_views || 0;
          const curRep = t.reported_views || 0;
          const deductCount = Math.min(remainingToDeduct, Math.max(curApp, curRep));
          if (deductCount > 0) {
            const newApp = Math.max(0, curApp - deductCount);
            const newRep = Math.max(0, curRep - deductCount);
            const newRew = Math.max(0, newApp * (t.reward_rate_ksh || rate));
            await env.DB.prepare(`
              UPDATE task_submissions
              SET approved_views = ?,
                  reported_views = ?,
                  reward_amount_ksh = ?,
                  admin_notes = ?,
                  reviewed_by = ?,
                  reviewed_at = ?
              WHERE id = ?
            `).bind(newApp, newRep, newRew, note, admin.id, now, t.id).run();
            remainingToDeduct -= deductCount;
          }
        }
      }

      // Record wallet transaction
      const txId = generateId('tx');
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        target.id,
        rewardKsh,
        nextAvailBal,
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
        details: { views, rate, rewardKsh, note, userEmail: target.email, availableBalanceKsh: nextAvailBal, viewsBalanceKsh: nextViewsBal },
        ip
      });

      return jsonSuccess({
        message: `Successfully adjusted ${views >= 0 ? '+' : ''}${views} views (${rewardKsh >= 0 ? '+KSh ' : '-KSh '}${Math.abs(rewardKsh).toLocaleString()}) for ${target.name}! New Available Balance: KSh ${nextAvailBal.toLocaleString()}.`,
        views,
        rate,
        rewardKsh,
        availableBalanceKsh: nextAvailBal,
        viewsBalanceKsh: nextViewsBal
      });

    } else if (action === 'modify_balance' || action === 'adjust_balance') {
      let balanceType = 'views';
      if (body.balanceType === 'referrals' || body.balanceType === 'referral') {
        balanceType = 'referrals';
      } else if (body.balanceType === 'surveys' || body.balanceType === 'survey') {
        balanceType = 'surveys';
      }
      const rawAmountStr = String(body.amount ?? body.amountKsh ?? '').trim();
      const note = (body.note || body.reason || 'Admin wallet balance modification').trim();

      // Ensure user has a wallet
      let wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      if (!wallet) {
        const walletId = generateId('wal');
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, target.id, now).run().catch(() => {});
        wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(target.id).first();
      }

      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curSurveys = wallet?.surveys_balance_ksh || 0;
      const curViews = ((wallet?.views_balance_ksh || 0) === 0 && curAvail > (curRef + curSurveys))
        ? (curAvail - curRef - curSurveys)
        : (wallet?.views_balance_ksh || 0);

      let deltaKsh = 0;
      if (body.mode === 'set' || rawAmountStr.startsWith('=')) {
        const targetAmount = parseInt(rawAmountStr.replace(/^=/, ''), 10);
        if (isNaN(targetAmount) || targetAmount < 0) {
          return jsonError('Please enter a valid non-negative balance amount in KSh', 400);
        }
        if (balanceType === 'referrals') {
          deltaKsh = targetAmount - curRef;
        } else if (balanceType === 'surveys') {
          deltaKsh = targetAmount - curSurveys;
        } else {
          deltaKsh = targetAmount - curViews;
        }
      } else {
        deltaKsh = parseInt(rawAmountStr, 10);
      }

      if (isNaN(deltaKsh) || deltaKsh === 0) {
        return jsonError('Please enter a valid non-zero balance change in KSh (e.g. 1000, -500, or =5000)', 400);
      }

      const nextViewsBal = balanceType === 'views' ? Math.max(0, curViews + deltaKsh) : curViews;
      const nextRefBal = balanceType === 'referrals' ? Math.max(0, curRef + deltaKsh) : curRef;
      const nextSurveysBal = balanceType === 'surveys' ? Math.max(0, curSurveys + deltaKsh) : curSurveys;
      const nextAvailBal = Math.max(0, nextViewsBal + nextRefBal + nextSurveysBal);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + deltaKsh);

      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            referrals_balance_ksh = ?,
            surveys_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextRefBal, nextSurveysBal, nextAvailBal, nextLifetime, now, target.id).run();

      const txId = generateId('tx');
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        target.id,
        deltaKsh,
        nextAvailBal,
        admin.id,
        `Admin ${balanceType === 'referrals' ? 'Referral' : 'Status Views'} balance adjustment: ${deltaKsh >= 0 ? '+KSh ' : '-KSh '}${Math.abs(deltaKsh).toLocaleString()} (${note})`,
        now
      ).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'ADMIN_MODIFY_BALANCE',
        targetType: 'user',
        targetId: target.id,
        details: { balanceType, deltaKsh, viewsBalanceKsh: nextViewsBal, referralsBalanceKsh: nextRefBal, availableBalanceKsh: nextAvailBal, note, userEmail: target.email },
        ip
      });

      return jsonSuccess({
        message: `Updated ${target.name}'s ${balanceType === 'referrals' ? 'Referral' : 'Status Views'} balance by ${deltaKsh >= 0 ? '+KSh ' : '-KSh '}${Math.abs(deltaKsh).toLocaleString()}! Total Available Balance: KSh ${nextAvailBal.toLocaleString()}.`,
        balanceType,
        deltaKsh,
        viewsBalanceKsh: nextViewsBal,
        referralsBalanceKsh: nextRefBal,
        availableBalanceKsh: nextAvailBal
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
