// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: POST /api/auth/login
// ====================================================================

import { jsonError, jsonSuccess, verifyPassword, generateToken, checkRateLimit, recordFailedAttempt, clearRateLimit } from '../_utils.js';

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
  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'default_ip';

  // 1. Rate Limiting Check (Maximum 3 attempts)
  const ipCheck = await checkRateLimit(env, `login:ip:${ip}`);
  if (!ipCheck.allowed) {
    return jsonError(`Too many login attempts from this network (3 attempts reached). Please wait ${ipCheck.waitMinutes || 5} minute(s) before trying again.`, 429);
  }

  const emailCheck = await checkRateLimit(env, `login:email:${cleanEmail}`);
  if (!emailCheck.allowed) {
    return jsonError(`Account access temporarily locked due to 3 failed login attempts. Please wait ${emailCheck.waitMinutes || 5} minute(s) before trying again.`, 429);
  }

  try {
    // 2. Fetch user by email
    let user = await env.DB.prepare(`
      SELECT id, name, email, phone, password_hash, salt, role, status
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(cleanEmail).first();

    // Auto-provision or reconcile the requested Administrator credentials
    if (cleanEmail === 'almai@admin.co.ke' && password === 'almai12345') {
      const adminSalt = 'a1b2c3d4e5f60718293a4b5c6d7e8f90';
      const adminHash = '34d565655f84920c15ea79180a187359f904bb2bee5e667b78ae3a0258e84ca3';
      const now = Math.floor(Date.now() / 1000);

      if (!user) {
        const adminId = 'usr_admin_almai';
        await env.DB.prepare(`
          INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
          VALUES (?, 'Almai Administrator', 'almai@admin.co.ke', '0700000000', ?, ?, 'admin', 'active', ?, ?)
        `).bind(adminId, adminHash, adminSalt, now, now).run();

        await env.DB.prepare(`
          INSERT OR IGNORE INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES ('wal_admin_almai', ?, 0, 0, 0, 0, ?)
        `).bind(adminId, now).run();

        user = {
          id: adminId,
          name: 'Almai Administrator',
          email: 'almai@admin.co.ke',
          phone: '0700000000',
          password_hash: adminHash,
          salt: adminSalt,
          role: 'admin',
          status: 'active'
        };
      } else if (user.role !== 'admin' || user.password_hash !== adminHash) {
        await env.DB.prepare(`
          UPDATE users SET role = 'admin', password_hash = ?, salt = ?, status = 'active', updated_at = ? WHERE id = ?
        `).bind(adminHash, adminSalt, now, user.id).run();
        user.role = 'admin';
        user.status = 'active';
        user.password_hash = adminHash;
        user.salt = adminSalt;
      }
    }

    if (!user) {
      // Prevent timing attacks by computing a dummy hash if user doesn't exist
      await verifyPassword(password, '00'.repeat(32), '00'.repeat(16));
      const failRecord = await recordFailedAttempt(env, `login:email:${cleanEmail}`, 300);
      await recordFailedAttempt(env, `login:ip:${ip}`, 300);
      if (failRecord.locked) {
        return jsonError('Too many failed login attempts (3 of 3). Your account access is locked for 5 minutes for your security.', 429);
      }
      return jsonError(`Invalid email or password. You have ${failRecord.remaining} attempt(s) remaining before temporary lockout.`, 401);
    }

    if (user.status !== 'active') {
      return jsonError('Your account has been suspended. Please contact support.', 403);
    }

    // 3. Verify password hash
    const isValid = await verifyPassword(password, user.password_hash, user.salt);
    if (!isValid) {
      const failRecord = await recordFailedAttempt(env, `login:email:${cleanEmail}`, 300);
      await recordFailedAttempt(env, `login:ip:${ip}`, 300);
      if (failRecord.locked) {
        return jsonError('Too many failed login attempts (3 of 3). Your account access is locked for 5 minutes for your security.', 429);
      }
      return jsonError(`Invalid email or password. You have ${failRecord.remaining} attempt(s) remaining before temporary lockout.`, 401);
    }

    // Successful login: clear rate limits
    await clearRateLimit(env, `login:email:${cleanEmail}`);
    await clearRateLimit(env, `login:ip:${ip}`);

    // 4. Issue new session token with 2 minutes inactivity timeout
    const sessionToken = generateToken(32);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 120; // 2 minutes of inactivity sliding session
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

    // 5. Fetch user package status (active or pending verification)
    const activePackage = await env.DB.prepare(`
      SELECT up.package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, up.status
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      WHERE up.user_id = ? AND up.status = 'active'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();

    const pendingPackage = await env.DB.prepare(`
      SELECT up.package_id, p.name, p.slug, p.price_ksh, up.status, pt.mpesa_receipt_number
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      LEFT JOIN payment_transactions pt ON pt.user_id = up.user_id AND pt.package_id = up.package_id AND pt.status = 'pending'
      WHERE up.user_id = ? AND up.status = 'pending_verification'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();

    const cookieHeader = `almai_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;

    return jsonSuccess({
      message: 'Sign in successful. Welcome back!',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      hasActivePackage: Boolean(activePackage),
      activePackage: activePackage || null,
      pendingPackage: pendingPackage || null,
      token: sessionToken
    }, 200, {
      'Set-Cookie': cookieHeader
    });

  } catch (err) {
    console.error('Login error:', err);
    return jsonError('Sign in failed due to a server error. Please try again.', 500);
  }
}
