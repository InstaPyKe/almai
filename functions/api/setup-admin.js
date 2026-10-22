// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: POST /api/setup-admin
// Secure Administrative Account Provisioning
// ====================================================================

import { jsonError, jsonSuccess } from './_utils.js';

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

  const { email, setupSecret } = body;

  if (!email || !setupSecret) {
    return jsonError('Both target user email and setupSecret are required', 400);
  }

  // Check setup secret against environment variable or fallback secure key
  const configuredSecret = env.ADMIN_SETUP_SECRET;
  if (!configuredSecret) {
    return jsonError('ADMIN_SETUP_SECRET has not been set in Cloudflare environment secrets. Administrator promotion is locked.', 403);
  }

  if (setupSecret !== configuredSecret) {
    return jsonError('Invalid administrator setup secret key', 401);
  }

  try {
    const cleanEmail = email.trim().toLowerCase();
    const user = await env.DB.prepare('SELECT id, name, email, role FROM users WHERE email = ?').bind(cleanEmail).first();

    if (!user) {
      return jsonError(`No registered user found with email ${cleanEmail}. Please register the account first.`, 404);
    }

    if (user.role === 'admin') {
      return jsonSuccess({ message: `User ${cleanEmail} is already an administrator.` });
    }

    await env.DB.prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?")
      .bind(Math.floor(Date.now() / 1000), user.id).run();

    return jsonSuccess({
      message: `User ${user.name} (${cleanEmail}) has been successfully promoted to Administrator!`,
      userId: user.id,
      role: 'admin'
    });

  } catch (err) {
    console.error('Setup admin error:', err);
    return jsonError('Failed to promote user to administrator', 500);
  }
}
