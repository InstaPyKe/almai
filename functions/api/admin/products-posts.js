// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST, DELETE /api/admin/products-posts
// Protected Administrator WhatsApp Product Creatives Management
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

/**
 * GET /api/admin/products-posts
 * Retrieve all product posts (active and archived)
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const { results } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, caption, image_url, image_base64, image_name, status, downloads_count, created_at
      FROM product_posts
      ORDER BY created_at DESC
      LIMIT 100
    `).all();

    return jsonSuccess({
      productPosts: results || []
    });

  } catch (err) {
    console.error('Admin fetch product posts error:', err);
    return jsonError('Failed to fetch product posts for admin', 500);
  }
}

/**
 * POST /api/admin/products-posts
 * Publish a new product picture for users to download and post on WhatsApp
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

  const { title, brandName, description, caption, imageBase64, imageName } = body;

  if (!title || typeof title !== 'string' || title.trim().length < 3) {
    return jsonError('Please enter a valid product title (at least 3 characters)', 400);
  }

  if (!brandName || typeof brandName !== 'string' || brandName.trim().length < 2) {
    return jsonError('Please enter a valid brand or company name', 400);
  }

  if (!caption || typeof caption !== 'string' || caption.trim().length < 5) {
    return jsonError('Please provide the suggested WhatsApp caption for users to copy', 400);
  }

  if (!imageBase64 || typeof imageBase64 !== 'string') {
    return jsonError('Product picture image file is required', 400);
  }

  // Check image size limit (5MB base64)
  if (imageBase64.length > 5 * 1024 * 1024) {
    return jsonError('Product image file is too large. Please upload an image under 3.5MB.', 400);
  }

  try {
    const postId = generateId('prod');
    const now = Math.floor(Date.now() / 1000);
    const cleanTitle = title.trim();
    const cleanBrand = brandName.trim();
    const cleanDesc = (description || '').trim();
    const cleanCaption = caption.trim();
    const fileName = imageName || 'whatsapp_promo.png';

    // 1. Insert into product_posts table
    await env.DB.prepare(`
      INSERT INTO product_posts (
        id, title, brand_name, description, caption, image_base64, image_name, status, downloads_count, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0, ?)
    `).bind(
      postId,
      cleanTitle,
      cleanBrand,
      cleanDesc,
      cleanCaption,
      imageBase64,
      fileName,
      now
    ).run();

    // 2. Also register as an active campaign so users can submit 24h proofs against it
    const campaignId = `camp_${postId}`;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO campaigns (id, title, brand_name, description, guidelines, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?)
    `).bind(
      campaignId,
      cleanTitle,
      cleanBrand,
      cleanDesc || `Campaign for ${cleanTitle}`,
      cleanCaption,
      now
    ).run();

    // 3. Audit Log
    const ip = request.headers.get('cf-connecting-ip') || '';
    await createAuditLog(env, {
      adminId: admin.id,
      action: 'POST_WHATSAPP_PRODUCT',
      targetType: 'product_post',
      targetId: postId,
      details: { title: cleanTitle, brand: cleanBrand, file: fileName },
      ip
    });

    return jsonSuccess({
      message: `Product creative "${cleanTitle}" posted successfully! It is now live for all users to download.`,
      product: {
        id: postId,
        title: cleanTitle,
        brand_name: cleanBrand,
        caption: cleanCaption,
        downloads_count: 0,
        created_at: now
      }
    }, 201);

  } catch (err) {
    console.error('Admin post product creative error:', err);
    return jsonError('Failed to publish product creative. Please try again.', 500);
  }
}

/**
 * DELETE /api/admin/products-posts
 * Delete or archive product creative
 */
export async function onRequestDelete(context) {
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

  const { postId } = body;

  if (!postId) {
    return jsonError('postId is required', 400);
  }

  try {
    const existing = await env.DB.prepare('SELECT id, title FROM product_posts WHERE id = ?').bind(postId).first();
    if (!existing) {
      return jsonError('Product post not found', 404);
    }

    await env.DB.prepare('DELETE FROM product_posts WHERE id = ?').bind(postId).run();

    // Audit log
    const ip = request.headers.get('cf-connecting-ip') || '';
    await createAuditLog(env, {
      adminId: admin.id,
      action: 'DELETE_PRODUCT_POST',
      targetType: 'product_post',
      targetId: postId,
      details: { title: existing.title },
      ip
    });

    return jsonSuccess({
      message: `Product creative "${existing.title}" has been deleted.`
    });

  } catch (err) {
    console.error('Delete product post error:', err);
    return jsonError('Failed to delete product post', 500);
  }
}
