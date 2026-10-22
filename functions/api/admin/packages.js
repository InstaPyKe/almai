// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, PUT /api/admin/packages
// Protected Administrator Package Configuration
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const { results } = await env.DB.prepare('SELECT * FROM packages ORDER BY price_ksh ASC').all();
    return jsonSuccess({ packages: results || [] });
  } catch (err) {
    return jsonError('Failed to fetch packages for admin', 500);
  }
}

export async function onRequestPut(context) {
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

  const { id, name, priceKsh, rewardPerViewKsh, maxViewsPerTask, isActive, features, badge } = body;

  if (!id) {
    return jsonError('Package ID is required', 400);
  }

  try {
    const existing = await env.DB.prepare('SELECT * FROM packages WHERE id = ?').bind(id).first();
    if (!existing) {
      return jsonError('Package not found', 404);
    }

    const price = priceKsh !== undefined ? parseInt(priceKsh, 10) : existing.price_ksh;
    const reward = rewardPerViewKsh !== undefined ? parseInt(rewardPerViewKsh, 10) : existing.reward_per_view_ksh;
    const maxViews = maxViewsPerTask !== undefined ? parseInt(maxViewsPerTask, 10) : existing.max_views_per_task;
    const active = isActive !== undefined ? (isActive ? 1 : 0) : existing.is_active;
    const pkgName = name || existing.name;
    const pkgBadge = badge !== undefined ? badge : existing.badge;
    const pkgFeatures = features ? (typeof features === 'string' ? features : JSON.stringify(features)) : existing.features;

    await env.DB.prepare(`
      UPDATE packages
      SET name = ?, price_ksh = ?, reward_per_view_ksh = ?, max_views_per_task = ?,
          is_active = ?, badge = ?, features = ?
      WHERE id = ?
    `).bind(pkgName, price, reward, maxViews, active, pkgBadge, pkgFeatures, id).run();

    await createAuditLog(env, {
      adminId: admin.id,
      action: 'UPDATE_PACKAGE',
      targetType: 'package',
      targetId: id,
      details: { name: pkgName, price, reward, maxViews, active }
    });

    return jsonSuccess({
      message: 'Package updated successfully',
      package: { id, name: pkgName, price_ksh: price, reward_per_view_ksh: reward, max_views_per_task: maxViews, is_active: active }
    });

  } catch (err) {
    console.error('Update package error:', err);
    return jsonError('Failed to update package', 500);
  }
}
