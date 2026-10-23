// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/users
// Protected Administrator User Directory & Account Management
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

/**
 * GET /api/admin/users
 * Search and retrieve users with financial & package profiles
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const url = new URL(request.url);
    const search = url.searchParams.get('q') || '';

    let query = `
      SELECT 
        u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
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

  const { targetUserId, action, packageId, newStatus, newRole } = body;

  if (!targetUserId || !action) {
    return jsonError('targetUserId and action are required', 400);
  }

  try {
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

    } else {
      return jsonError('Invalid action specified', 400);
    }

  } catch (err) {
    console.error('Admin user action error:', err);
    return jsonError('Failed to perform user administrative action', 500);
  }
}
