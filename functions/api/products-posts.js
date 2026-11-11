// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/products-posts
// WhatsApp Products & Promotional Creatives for Partner Downloads
// ====================================================================

import { jsonError, jsonSuccess, authenticate, syncAndGetUserPackageState, TRIAL_EXPIRED_LOCKOUT_MESSAGE } from './_utils.js';

/**
 * GET /api/products-posts
 * Returns full active product posts only to active partners / admins;
 * public visitors & non-active accounts receive only a 3-item preview sample.
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  if (!env.DB) {
    return jsonError('Database configuration missing', 500);
  }

  try {
    const authUser = await authenticate(request, env).catch(() => null);
    let hasFullAccess = false;

    if (authUser) {
      if (authUser.role === 'admin') {
        hasFullAccess = true;
      } else {
        const pkgState = await syncAndGetUserPackageState(env.DB, authUser.id);
        hasFullAccess = Boolean(pkgState.activePackage && !pkgState.isTrialExpiredLockout);
      }
    }

    const PUBLIC_SAMPLE_LIMIT = 3;
    const countRow = await env.DB.prepare(`
      SELECT COUNT(*) as total
      FROM product_posts
      WHERE status = 'active'
    `).first();
    const totalCount = Number(countRow?.total || 0);

    const queryLimit = hasFullAccess ? 50 : PUBLIC_SAMPLE_LIMIT;
    const { results } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, caption, image_url, image_base64, image_name, downloads_count, created_at
      FROM product_posts
      WHERE status = 'active'
      ORDER BY created_at DESC
      LIMIT ?
    `).bind(queryLimit).all();

    return jsonSuccess({
      posts: results || [],
      productPosts: results || [],
      isPublicSample: !hasFullAccess,
      hasFullAccess,
      totalCount,
      sampleLimit: hasFullAccess ? null : PUBLIC_SAMPLE_LIMIT
    }, 200, {
      'Cache-Control': 'private, no-store'
    });

  } catch (err) {
    console.error('Fetch product posts error:', err);
    return jsonError('Failed to fetch promotional WhatsApp product posts', 500);
  }
}

/**
 * POST /api/products-posts
 * Track product image download count (active partners & admins only)
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.DB) {
    return jsonError('Database configuration missing', 500);
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const targetId = body?.id || body?.postId;

  if (!targetId) {
    return jsonError('Product ID is required', 400);
  }

  try {
    const authUser = await authenticate(request, env).catch(() => null);
    if (!authUser) {
      return jsonError('Sign in with an active partner package to download product creatives.', 401);
    }

    if (authUser.role !== 'admin') {
      const pkgState = await syncAndGetUserPackageState(env.DB, authUser.id);
      if (pkgState.isTrialExpiredLockout) {
        return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: 'TRIAL_EXPIRED' });
      }
      if (!pkgState.activePackage) {
        return jsonError('Active partner package required to download daily product creatives.', 403, { packageRequired: true });
      }
    }

    await env.DB.prepare(`
      UPDATE product_posts
      SET downloads_count = downloads_count + 1
      WHERE id = ?
    `).bind(targetId).run();

    return jsonSuccess({ message: 'Download tracked successfully' });
  } catch (err) {
    return jsonError('Failed to track download event', 500);
  }
}
