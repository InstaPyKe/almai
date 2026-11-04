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
    const waitMins = ipCheck.waitMinutes || 5;
    return jsonError(`Too many login attempts from this network (3 trials reached). Please wait ${waitMins} minute(s) before trying again.`, 429, {
      attempts: 3,
      remaining: 0,
      locked: true,
      waitMinutes: waitMins,
      waitSeconds: ipCheck.waitSeconds || (waitMins * 60)
    });
  }

  const emailCheck = await checkRateLimit(env, `login:email:${cleanEmail}`);
  if (!emailCheck.allowed) {
    const waitMins = emailCheck.waitMinutes || 5;
    return jsonError(`Account access temporarily locked due to 3 failed login attempts. Please wait ${waitMins} minute(s) before trying again.`, 429, {
      attempts: 3,
      remaining: 0,
      locked: true,
      waitMinutes: waitMins,
      waitSeconds: emailCheck.waitSeconds || (waitMins * 60)
    });
  }

  try {
    // 2. Fetch user by email
    let user = await env.DB.prepare(`
      SELECT id, name, email, phone, password_hash, salt, role, status, referral_code, referred_by
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(cleanEmail).first();

    // Auto-provision or reconcile the authorized Administrator credentials
    if (cleanEmail === 'mentorbravin@gmail.com' && (password === '@mentor123' || password === 'Mentor@2026')) {
      const adminSalt = 'b7e2c9d1a4f50827364b5c6d7e8f9102';
      const adminHash = password === '@mentor123'
        ? 'cff8eb4c84f09df856787f33a136c771810d2ac6376440107e13c6e766613ac9'
        : 'a1194e448c3ef0848f7884c1b3475daa750717a16d591efb0121cf442b5bee7e';
      const now = Math.floor(Date.now() / 1000);

      if (!user) {
        const adminId = 'usr_admin_mentorbravin';
        await env.DB.prepare(`
          INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
          VALUES (?, 'Bravin Mentor (Admin)', 'mentorbravin@gmail.com', '0700000000', ?, ?, 'admin', 'active', ?, ?)
        `).bind(adminId, adminHash, adminSalt, now, now).run();

        await env.DB.prepare(`
          INSERT OR IGNORE INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES ('wal_admin_mentorbravin', ?, 0, 0, 0, 0, ?)
        `).bind(adminId, now).run();

        user = {
          id: adminId,
          name: 'Bravin Mentor (Admin)',
          email: 'mentorbravin@gmail.com',
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

    // Strict admin role enforcement: Only mentorbravin@gmail.com can log in as or hold the admin role
    if (user && user.role === 'admin' && user.email.toLowerCase() !== 'mentorbravin@gmail.com') {
      user.role = 'user';
      await env.DB.prepare("UPDATE users SET role = 'user' WHERE id = ?").bind(user.id).run().catch(() => { });
    }

    if (!user) {
      // Prevent timing attacks by computing a dummy hash if user doesn't exist
      await verifyPassword(password, '00'.repeat(32), '00'.repeat(16));
      const failRecord = await recordFailedAttempt(env, `login:email:${cleanEmail}`, 300);
      await recordFailedAttempt(env, `login:ip:${ip}`, 300);
      if (failRecord.locked) {
        return jsonError('Too many failed sign-in attempts (3 of 3 trials used). Access is locked for 5 minutes for security.', 429, {
          attempts: 3,
          remaining: 0,
          locked: true,
          waitMinutes: 5,
          waitSeconds: 300
        });
      }
      return jsonError(`Invalid email or password. Trial ${failRecord.attempts} of 3 used (${failRecord.remaining} attempt${failRecord.remaining === 1 ? '' : 's'} remaining).`, 401, {
        attempts: failRecord.attempts,
        remaining: failRecord.remaining,
        locked: false
      });
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
        return jsonError('Too many failed sign-in attempts (3 of 3 trials used). Access is locked for 5 minutes for security.', 429, {
          attempts: 3,
          remaining: 0,
          locked: true,
          waitMinutes: 5,
          waitSeconds: 300
        });
      }
      return jsonError(`Invalid email or password. Trial ${failRecord.attempts} of 3 used (${failRecord.remaining} attempt${failRecord.remaining === 1 ? '' : 's'} remaining).`, 401, {
        attempts: failRecord.attempts,
        remaining: failRecord.remaining,
        locked: false
      });
    }

    // Successful login: clear rate limits
    await clearRateLimit(env, `login:email:${cleanEmail}`);
    await clearRateLimit(env, `login:ip:${ip}`);

    // 4. Issue new session token with 7 days expiration
    const sessionToken = generateToken(32);
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = now + 7 * 86400; // 7 days session
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

    const isHttps = request.url.startsWith('https://');
    const cookieHeader = `almai_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${isHttps ? '; Secure' : ''}`;

    // Ensure user has a referral code
    let refCode = user.referral_code;
    if (!refCode) {
      refCode = 'ALM' + user.id.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase();
      await env.DB.prepare('UPDATE users SET referral_code = ? WHERE id = ?').bind(refCode, user.id).run().catch(() => { });
    }

    return jsonSuccess({
      message: 'Sign in successful. Welcome back!',
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        referralCode: refCode
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
