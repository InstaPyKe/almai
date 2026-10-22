// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: POST /api/auth/login
// ====================================================================

import { jsonError, jsonSuccess, verifyPassword, generateToken } from '../_utils.js';

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

  const { email, password } = body;

  if (!email || !password) {
    return jsonError('Email and password are required', 400);
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    // 1. Fetch user by email
    const user = await env.DB.prepare(`
      SELECT id, name, email, phone, password_hash, salt, role, status
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(cleanEmail).first();

    if (!user) {
      // Prevent timing attacks by computing a dummy hash if user doesn't exist
      await verifyPassword(password, '00'.repeat(32), '00'.repeat(16));
      return jsonError('Invalid email or password', 401);
    }

    if (user.status !== 'active') {
      return jsonError('Your account has been suspended. Please contact support.', 403);
    }

    // 2. Verify password hash
    const isValid = await verifyPassword(password, user.password_hash, user.salt);
    if (!isValid) {
      return jsonError('Invalid email or password', 401);
    }

    // 3. Issue new session token
    const sessionToken = generateToken(32);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + (7 * 24 * 60 * 60); // 7 days
    const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || '';
    const userAgent = request.headers.get('user-agent') || '';

    await env.DB.prepare(`
      INSERT INTO sessions (id, user_id, expires_at, created_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      sessionToken,
      user.id,
      expiresAt,
      now,
      ip,
      userAgent
    ).run();

    const cookieHeader = `almai_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 86400}`;

    return jsonSuccess({
      message: 'Sign in successful. Welcome back!',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      token: sessionToken
    }, 200, {
      'Set-Cookie': cookieHeader
    });

  } catch (err) {
    console.error('Login error:', err);
    return jsonError('Sign in failed due to a server error. Please try again.', 500);
  }
}
