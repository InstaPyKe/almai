// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/products-posts
// WhatsApp Products & Promotional Creatives for Partner Downloads
// ====================================================================

import { jsonError, jsonSuccess } from './_utils.js';

/**
 * GET /api/products-posts
 * Fetch active promotional product pictures and captions for WhatsApp Status
 */
export async function onRequestGet(context) {
  const { env } = context;

  if (!env.DB) {
    return jsonError('Database configuration missing', 500);
  }

  try {
    const { results } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, caption, image_url, image_base64, image_name, downloads_count, created_at
      FROM product_posts
      WHERE status = 'active'
      ORDER BY created_at DESC
      LIMIT 50
    `).all();

    return jsonSuccess({
      posts: results || [],
      productPosts: results || []
    });

  } catch (err) {
    console.error('Fetch product posts error:', err);
    return jsonError('Failed to fetch promotional WhatsApp product posts', 500);
  }
}

/**
 * POST /api/products-posts
 * Track product image download count
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
