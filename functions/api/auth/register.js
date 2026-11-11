// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: POST /api/auth/register
// ====================================================================

import { jsonError, jsonSuccess, hashPassword, generateId, generateToken, checkRateLimit, recordFailedAttempt, verifyRecaptchaToken, ensureAuthReferralSchema } from '../_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  if (!env.DB) {
    return jsonError('Database configuration missing', 500);
  }

  const ip = request.headers.get('cf-connecting-ip') || request.headers.get('x-forwarded-for') || 'default_ip';

  // Rate Limiting Check (Maximum 3 attempts)
  const regCheck = await checkRateLimit(env, `reg:ip:${ip}`);
  if (!regCheck.allowed) {
    return jsonError(`Too many registration attempts (3 attempts reached). For security, please wait ${regCheck.waitMinutes || 10} minute(s) before trying again.`, 429);
  }

  let body;

  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const { name, email, phone, password, referralCode } = body;
  const recaptchaToken = body.recaptchaToken || body['g-recaptcha-response'] || '';

  // 1. Validation
  if (!name || typeof name !== 'string' || name.trim().length < 2) {
    return jsonError('Valid full name is required (min 2 characters)', 400);
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError('Please provide a valid email address', 400);
  }

  if (!phone || typeof phone !== 'string' || phone.trim().length < 9) {
    return jsonError('Please provide a valid M-Pesa phone number (e.g. 0712345678 or 254712345678)', 400);
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    return jsonError('Password must be at least 8 characters long', 400);
  }

  // 1b. Verify Google reCAPTCHA response
  const captcha = await verifyRecaptchaToken(recaptchaToken, ip, env);
  if (!captcha.ok) {
    return jsonError(captcha.error, captcha.status || 400, {
      recaptchaRequired: true,
      codes: captcha.codes
    });
  }

  const cleanEmail = email.trim().toLowerCase();
  const cleanPhone = phone.trim().replace(/\s+/g, '');
  const cleanName = name.trim();
  const cleanReferral = (referralCode || '').trim();

  try {
    await ensureAuthReferralSchema(env.DB);

    // 2. Check if email already registered (case-insensitive)
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE LOWER(email) = ? LIMIT 1'
    ).bind(cleanEmail).first();

    if (existing) {
      await recordFailedAttempt(env, `reg:ip:${ip}`, 600);
      return jsonError('An account with this email address already exists. Please log in.', 409);
    }

    // Record registration attempt for rate-limiting (max 3 accounts per IP per 10 mins)
    await recordFailedAttempt(env, `reg:ip:${ip}`, 600);

    // Look up referrer if referral code provided
    let referrer = null;
    if (cleanReferral) {
      referrer = await env.DB.prepare(`
        SELECT id, name, email FROM users
        WHERE (id = ? OR referral_code = ? OR referral_code = ?) AND status = 'active'
        LIMIT 1
      `).bind(cleanReferral, cleanReferral, cleanReferral.toUpperCase()).first();
    }

    // 3. Hash password with PBKDF2-SHA256
    const { hash, salt } = await hashPassword(password);

    const userId = generateId('usr');
    const walletId = generateId('wal');
    const now = Math.floor(Date.now() / 1000);
    const myReferralCode = 'ALM' + generateToken(3).toUpperCase();
    const referredById = referrer ? referrer.id : null;

    // 4. Default user role is always 'user'
    const initialRole = 'user';

    // 5. Insert User with Referral Code and Referrer
    await env.DB.prepare(`
      INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, referral_code, referred_by, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)
    `).bind(
      userId,
      cleanName,
      cleanEmail,
      cleanPhone,
      hash,
      salt,
      initialRole,
      myReferralCode,
      referredById,
      now,
      now
    ).run();

    // 6. Record Referral Tracking record if referred
    if (referrer) {
      const refTrackingId = generateId('ref');
      await env.DB.prepare(`
        INSERT INTO referrals (id, referrer_id, referred_user_id, referral_code, status, created_at)
        VALUES (?, ?, ?, ?, 'registered', ?)
      `).bind(refTrackingId, referrer.id, userId, cleanReferral, now).run().catch(() => {});
    }

    // 7. Initialize Wallet
    await env.DB.prepare(`
      INSERT INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
      VALUES (?, ?, 0, 0, 0, 0, ?)
    `).bind(walletId, userId, now).run();

    // 8. Return registration success requiring subsequent login
    return jsonSuccess({
      message: referrer
        ? `Registration successful! You were invited by ${referrer.name}. Please sign in to activate your partner package.`
        : 'Registration successful! Please log in with your email and password to choose and activate your partner package.',
      registered: true,
      email: cleanEmail,
      referralCode: myReferralCode,
      referredBy: referrer ? referrer.name : null
    }, 201);

  } catch (err) {
    console.error('Registration error:', err);
    return jsonError('Registration failed due to a server error. Please try again.', 500);
  }
}
