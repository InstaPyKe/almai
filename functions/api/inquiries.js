// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/inquiries
// ====================================================================

import { jsonError, jsonSuccess, authenticate, generateId } from './_utils.js';

/**
 * POST /api/inquiries
 * Submit a business marketing inquiry for Almai advertising services
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

  const { name, email, phone, businessName, serviceType, budgetRange, message } = body;

  if (!name || name.trim().length < 2) {
    return jsonError('Please provide your name or company representative name', 400);
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError('Please provide a valid contact email address', 400);
  }

  if (!phone || phone.trim().length < 8) {
    return jsonError('Please provide a valid phone number for our media team to reach you', 400);
  }

  if (!message || message.trim().length < 10) {
    return jsonError('Please include a brief message detailing your advertising goals (min 10 characters)', 400);
  }

  try {
    // Check if user is currently signed in
    const authUser = await authenticate(request, env);
    const inquiryId = generateId('inq');
    const now = Math.floor(Date.now() / 1000);

    await env.DB.prepare(`
      INSERT INTO service_inquiries (
        id, user_id, name, email, phone, business_name, service_type, budget_range, message, status, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
    `).bind(
      inquiryId,
      authUser ? authUser.id : null,
      name.trim(),
      email.trim().toLowerCase(),
      phone.trim(),
      businessName ? businessName.trim() : 'Private Individual',
      serviceType || 'WhatsApp Status Network Blast',
      budgetRange || 'Flexible',
      message.trim(),
      now
    ).run();

    return jsonSuccess({
      message: 'Thank you! Your advertising inquiry has been submitted. Our commercial media strategist will contact you within 24 hours.',
      inquiryId
    }, 201);

  } catch (err) {
    console.error('Inquiry error:', err);
    return jsonError('Failed to record inquiry. Please try again.', 500);
  }
}

/**
 * GET /api/inquiries
 * Admin view of incoming business advertiser inquiries
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const authUser = await authenticate(request, env);
  if (!authUser || authUser.role !== 'admin') {
    return jsonError('Administrator access required', 403);
  }

  try {
    const { results } = await env.DB.prepare(`
      SELECT id, name, email, phone, business_name, service_type, budget_range, message, status, created_at
      FROM service_inquiries
      ORDER BY created_at DESC
      LIMIT 100
    `).all();

    return jsonSuccess({
      inquiries: results || []
    });

  } catch (err) {
    console.error('Fetch inquiries error:', err);
    return jsonError('Failed to fetch inquiries', 500);
  }
}
