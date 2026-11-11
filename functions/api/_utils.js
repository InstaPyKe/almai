// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions Utilities
// Web Crypto API, Session Verification, Database Bindings & Auth
// ====================================================================

/**
 * Standard JSON Response helper
 */
export function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'X-Content-Type-Options': 'nosniff',
      'Cache-Control': 'no-store',
      ...headers
    }
  });
}

export function jsonError(message, status = 400, details = null) {
  return jsonResponse({
    success: false,
    error: message,
    ...(details ? { details } : {})
  }, status);
}

export function jsonSuccess(data = {}, status = 200, headers = {}) {
  return jsonResponse({
    success: true,
    ...data
  }, status, headers);
}

/**
 * Generate cryptographically secure random IDs / tokens
 */
export function generateToken(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function generateId(prefix = 'id') {
  return `${prefix}_${generateToken(12)}`;
}

/**
 * Convert Buffer <-> Hex
 */
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Hash password using native Cloudflare Web Crypto (PBKDF2-SHA256)
 */
export async function hashPassword(password, saltHex = null) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveBits']
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  );
  return {
    hash: bufToHex(derivedBits),
    salt: bufToHex(salt)
  };
}

export async function verifyPassword(password, storedHash, storedSalt) {
  if (!password || !storedHash || !storedSalt) return false;
  try {
    const { hash } = await hashPassword(password, storedSalt);
    return hash === storedHash;
  } catch (err) {
    return false;
  }
}

/**
 * Parse cookies from request headers
 */
export function getCookie(request, name) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(';').map(c => c.trim());
  for (const cookie of cookies) {
    const [key, value] = cookie.split('=');
    if (key === name) {
      return decodeURIComponent(value);
    }
  }
  return null;
}

/**
 * Retrieve session token from Cookie or Authorization header
 */
export function getSessionToken(request) {
  const cookieToken = getCookie(request, 'almai_session');
  if (cookieToken) return cookieToken;

  const authHeader = request.headers.get('Authorization');
  if (authHeader && authHeader.startsWith('Bearer ')) {
    return authHeader.substring(7).trim();
  }
  return null;
}

/**
 * Authenticate session against D1
 */
export async function authenticate(request, env) {
  if (!env.DB) {
    throw new Error('Database binding "DB" is not configured in Cloudflare environment.');
  }

  const token = getSessionToken(request);
  if (!token) return null;

  const now = Math.floor(Date.now() / 1000);

  // Find valid session
  const session = await env.DB.prepare(`
    SELECT s.id as session_id, s.user_id, s.expires_at, 
           u.name, u.email, u.phone, u.role, u.status, u.referral_code
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ? AND u.status = 'active'
    LIMIT 1
  `).bind(token, now).first();

  if (!session) return null;

  // Enforce sliding 7-day session expiration
  const refreshedExpiresAt = now + 7 * 86400;
  env.DB.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').bind(refreshedExpiresAt, token).run().catch(() => {});

  const effectiveRole = (session.role === 'admin' && session.email && session.email.toLowerCase() === 'mentorbravin@gmail.com') ? 'admin' : (session.role === 'admin' ? 'user' : session.role);

  return {
    token,
    id: session.user_id,
    name: session.name,
    email: session.email,
    phone: session.phone,
    role: effectiveRole,
    referralCode: session.referral_code || ('ALM' + session.user_id.replace(/[^a-zA-Z0-9]/g, '').substring(0, 6).toUpperCase()),
    status: session.status
  };
}

/**
 * Authentication Gateways
 */
export async function requireAuth(request, env) {
  const user = await authenticate(request, env);
  if (!user) {
    return { errorResponse: jsonError('Session expired or authentication required. Please sign in.', 401) };
  }
  return { user };
}

export async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth;

  if (auth.user.role !== 'admin' || !auth.user.email || auth.user.email.toLowerCase() !== 'mentorbravin@gmail.com') {
    return { errorResponse: jsonError('Forbidden: Administrator privileges required.', 403) };
  }
  return { user: auth.user };
}

/**
 * Rate Limiting for Authentication (3 attempts limit)
 */
export async function checkRateLimit(env, key) {
  if (!env || !env.DB) return { allowed: true, remaining: 3, attempts: 0 };
  try {
    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB.prepare(`
      SELECT attempts, last_attempt, blocked_until 
      FROM rate_limits 
      WHERE key = ? 
      LIMIT 1
    `).bind(key).first();

    if (!row) return { allowed: true, remaining: 3, attempts: 0 };

    // If currently locked out and time remains
    if (row.blocked_until && row.blocked_until > now) {
      const waitSeconds = row.blocked_until - now;
      return {
        allowed: false,
        remaining: 0,
        attempts: row.attempts,
        waitSeconds,
        waitMinutes: Math.ceil(waitSeconds / 60),
        locked: true
      };
    }

    // If lockout period has expired, reset attempts to grant fresh trials
    if (row.blocked_until && row.blocked_until <= now) {
      await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(key).run().catch(() => {});
      return { allowed: true, remaining: 3, attempts: 0, locked: false };
    }

    // Reset if window of 10 minutes has passed
    if (now - row.last_attempt > 600) {
      await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(key).run().catch(() => {});
      return { allowed: true, remaining: 3, attempts: 0, locked: false };
    }

    const remaining = Math.max(0, 3 - (row.attempts || 0));
    return {
      allowed: (row.attempts || 0) < 3,
      remaining,
      attempts: row.attempts || 0,
      locked: (row.attempts || 0) >= 3
    };
  } catch (err) {
    // Auto-create table if missing
    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          attempts INTEGER NOT NULL DEFAULT 1,
          last_attempt INTEGER NOT NULL,
          blocked_until INTEGER NOT NULL DEFAULT 0
        )
      `).run();
    } catch (e) {}
    return { allowed: true, remaining: 3, attempts: 0, locked: false };
  }
}

export async function recordFailedAttempt(env, key, lockoutSeconds = 300) {
  if (!env || !env.DB) return { attempts: 1, remaining: 2, locked: false, waitSeconds: 0 };
  try {
    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB.prepare('SELECT attempts, last_attempt, blocked_until FROM rate_limits WHERE key = ?').bind(key).first();
    
    let currentAttempts = 1;
    if (row) {
      // If previous lockout or inactivity window expired, start fresh count
      if ((row.blocked_until && row.blocked_until <= now) || (now - row.last_attempt > 600)) {
        currentAttempts = 1;
      } else {
        currentAttempts = (row.attempts || 0) + 1;
      }
    }

    const isLocked = currentAttempts >= 3;
    const blockedUntil = isLocked ? now + lockoutSeconds : 0;

    await env.DB.prepare(`
      INSERT INTO rate_limits (key, attempts, last_attempt, blocked_until)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        attempts = excluded.attempts,
        last_attempt = excluded.last_attempt,
        blocked_until = CASE WHEN excluded.attempts >= 3 THEN ? ELSE 0 END
    `).bind(key, currentAttempts, now, blockedUntil, blockedUntil).run();

    return {
      attempts: currentAttempts,
      remaining: Math.max(0, 3 - currentAttempts),
      locked: isLocked,
      waitSeconds: isLocked ? lockoutSeconds : 0,
      waitMinutes: isLocked ? Math.ceil(lockoutSeconds / 60) : 0
    };
  } catch (err) {
    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          attempts INTEGER NOT NULL DEFAULT 1,
          last_attempt INTEGER NOT NULL,
          blocked_until INTEGER NOT NULL DEFAULT 0
        )
      `).run();
    } catch (e) {}
    return { attempts: 1, remaining: 2, locked: false, waitSeconds: 0 };
  }
}

export async function clearRateLimit(env, key) {
  if (!env || !env.DB) return;
  try {
    await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(key).run();
  } catch (err) {}
}

/**
 * Create Audit Log Entry
 */
export async function createAuditLog(env, { adminId, action, targetType, targetId, details = {}, ip = '' }) {
  try {
    const id = generateId('aud');
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(`
      INSERT INTO admin_audit_logs (id, admin_id, action, target_type, target_id, details, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      adminId,
      action,
      targetType,
      targetId,
      JSON.stringify(details),
      ip,
      now
    ).run();
  } catch (err) {
    console.error('Audit log creation failed:', err);
  }
}

/**
 * 45% Referral Commission Engine
 * Automatically distributes 45% of the activated package price to the verified referrer.
 */
export async function awardReferralCommission(env, userId, packageId, packageName, packagePriceKsh) {
  if (!env || !env.DB || !userId || !packagePriceKsh) return null;
  try {
    const now = Math.floor(Date.now() / 1000);
    // 1. Fetch user to verify referrer
    const user = await env.DB.prepare('SELECT id, name, email, referred_by FROM users WHERE id = ?').bind(userId).first();
    if (!user || !user.referred_by) return null;

    // Prevent circular or self referral
    if (user.referred_by === userId) return null;

    const referrer = await env.DB.prepare('SELECT id, name, email FROM users WHERE id = ?').bind(user.referred_by).first();
    if (!referrer) return null;

    // 45% commission calculation
    const commissionKsh = Math.round(Number(packagePriceKsh) * 0.45);
    if (commissionKsh <= 0) return null;

    // 2. Check existing referral record
    const existingRef = await env.DB.prepare('SELECT id, commission_paid FROM referrals WHERE referred_user_id = ? LIMIT 1').bind(userId).first();

    if (existingRef) {
      await env.DB.prepare(`
        UPDATE referrals
        SET status = 'active_paid',
            package_id = ?,
            package_name = ?,
            package_price_ksh = ?,
            commission_rate = 0.45,
            commission_amount_ksh = ?,
            commission_paid = 1,
            activated_at = ?
        WHERE id = ?
      `).bind(packageId, packageName, packagePriceKsh, commissionKsh, now, existingRef.id).run();
    } else {
      const refId = generateId('ref');
      await env.DB.prepare(`
        INSERT INTO referrals (id, referrer_id, referred_user_id, status, package_id, package_name, package_price_ksh, commission_rate, commission_amount_ksh, commission_paid, created_at, activated_at)
        VALUES (?, ?, ?, 'active_paid', ?, ?, ?, 0.45, ?, 1, ?, ?)
      `).bind(refId, referrer.id, userId, packageId, packageName, packagePriceKsh, commissionKsh, now, now).run();
    }

    // 3. Update Referrer's Wallet (available & lifetime)
    let referrerWallet = await env.DB.prepare('SELECT id, available_balance_ksh, lifetime_earnings_ksh FROM wallets WHERE user_id = ?').bind(referrer.id).first();
    if (!referrerWallet) {
      const walId = generateId('wal');
      await env.DB.prepare(`
        INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
        VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?)
      `).bind(walId, referrer.id, now).run();
      referrerWallet = { id: walId, available_balance_ksh: 0, views_balance_ksh: 0, referrals_balance_ksh: 0, lifetime_earnings_ksh: 0 };
    }

    const newAvailable = referrerWallet.available_balance_ksh + commissionKsh;
    const newLifetime = referrerWallet.lifetime_earnings_ksh + commissionKsh;

    await env.DB.prepare(`
      UPDATE wallets
      SET referrals_balance_ksh = referrals_balance_ksh + ?,
          available_balance_ksh = available_balance_ksh + ?,
          lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
          updated_at = ?
      WHERE id = ?
    `).bind(commissionKsh, commissionKsh, commissionKsh, now, referrerWallet.id).run();

    // 4. Record transparent transaction ledger entry
    const txId = generateId('wtx');
    await env.DB.prepare(`
      INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
      VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
    `).bind(
      txId,
      referrerWallet.id,
      referrer.id,
      commissionKsh,
      newAvailable,
      userId,
      `45% Referral Commission from ${user.name} (${packageName} - KSh ${packagePriceKsh})`,
      now
    ).run();

    return {
      referrerId: referrer.id,
      referrerName: referrer.name,
      commissionKsh
    };
  } catch (err) {
    console.error('awardReferralCommission error:', err);
    return null;
  }
}

export const TRIAL_EXPIRED_LOCKOUT_MESSAGE = 'Your 1-Day Free Trial has expired. Company services are locked until you upgrade to a paid partner package (Starter Pro, Exclusive, or Premium).';

const freeTrialSchemaReadyDbs = new WeakSet();
const authReferralSchemaReadyDbs = new WeakSet();

/**
 * Idempotently ensure users table has referral_code / referred_by columns
 * and referrals tracking table exists even on partially migrated D1 instances.
 */
export async function ensureAuthReferralSchema(db) {
  if (!db || authReferralSchemaReadyDbs.has(db)) return;

  await db.prepare('ALTER TABLE users ADD COLUMN referral_code TEXT').run().catch(() => {});
  await db.prepare('ALTER TABLE users ADD COLUMN referred_by TEXT').run().catch(() => {});
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS referrals (
      id TEXT PRIMARY KEY,
      referrer_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      referred_user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      referral_code TEXT,
      status TEXT NOT NULL DEFAULT 'registered' CHECK(status IN ('registered', 'active_paid')),
      package_id TEXT REFERENCES packages(id),
      package_name TEXT,
      package_price_ksh INTEGER DEFAULT 0,
      commission_rate REAL DEFAULT 0.45,
      commission_amount_ksh INTEGER DEFAULT 0,
      commission_paid INTEGER DEFAULT 0,
      created_at INTEGER NOT NULL,
      activated_at INTEGER
    )
  `).run().catch(() => {});
  await db.prepare(`
    UPDATE users
    SET referral_code = 'ALM' || UPPER(SUBSTR(REPLACE(REPLACE(id, 'usr_', ''), 'admin_', ''), 1, 6))
    WHERE referral_code IS NULL OR referral_code = ''
  `).run().catch(() => {});

  authReferralSchemaReadyDbs.add(db);
}

/**
 * Idempotently ensure packages table supports flexible timed free trials
 * without modifying any existing paid package plans.
 */
export async function ensureFreeTrialSchema(db) {
  if (!db || freeTrialSchemaReadyDbs.has(db)) return;

  await db.prepare('ALTER TABLE packages ADD COLUMN min_withdrawal_views_ksh INTEGER NOT NULL DEFAULT 5000').run().catch(() => {});
  await db.prepare('ALTER TABLE packages ADD COLUMN duration_hours INTEGER DEFAULT NULL').run().catch(() => {});
  await db.prepare('ALTER TABLE packages ADD COLUMN is_free_trial INTEGER NOT NULL DEFAULT 0').run().catch(() => {});

  const now = Math.floor(Date.now() / 1000);
  await db.prepare(`
    INSERT OR IGNORE INTO packages (
      id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task,
      min_withdrawal_views_ksh, features, badge, is_active, created_at,
      duration_hours, is_free_trial
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 24, 1)
  `).bind(
    'pkg_free_trial',
    '1-Day Free Trial',
    'free-trial',
    0,
    15,
    25,
    5000,
    JSON.stringify([
      'Free 24-hour full partner access',
      'Earn KSh 15 per approved view',
      'Up to 25 views per WhatsApp task',
      'Full Paid Surveys & Creative access',
      'Upgrade anytime to keep earning permanently'
    ]),
    'FREE 1-DAY TRIAL',
    now
  ).run().catch(() => {});

  freeTrialSchemaReadyDbs.add(db);
}

/**
 * Expire any timed package past expires_at and return the user's current
 * active/pending/expired-trial package state cleanly.
 */
export async function syncAndGetUserPackageState(db, userId, nowOverride = null) {
  await ensureFreeTrialSchema(db);
  const now = nowOverride !== null ? nowOverride : Math.floor(Date.now() / 1000);

  // Auto-expire any timed package whose 1-day (or configured) window has elapsed
  await db.prepare(`
    UPDATE user_packages
    SET status = 'expired'
    WHERE user_id = ?
      AND status = 'active'
      AND expires_at IS NOT NULL
      AND expires_at <= ?
  `).bind(userId, now).run().catch(() => {});

  const activePackage = await db.prepare(`
    SELECT up.id as user_package_id, up.status, up.activated_at, up.expires_at,
           p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh,
           p.max_views_per_task, p.min_withdrawal_views_ksh, p.badge,
           COALESCE(p.duration_hours, NULL) as duration_hours,
           COALESCE(p.is_free_trial, 0) as is_free_trial
    FROM user_packages up
    JOIN packages p ON up.package_id = p.id
    WHERE up.user_id = ?
      AND up.status = 'active'
      AND (up.expires_at IS NULL OR up.expires_at > ?)
    ORDER BY up.activated_at DESC
    LIMIT 1
  `).bind(userId, now).first();

  const pendingPackage = await db.prepare(`
    SELECT up.id as user_package_id, up.status, up.activated_at,
           p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.max_views_per_task, p.badge,
           pt.mpesa_receipt_number, pt.created_at as payment_submitted_at
    FROM user_packages up
    JOIN packages p ON up.package_id = p.id
    LEFT JOIN payment_transactions pt ON pt.user_id = up.user_id AND pt.package_id = up.package_id AND pt.status = 'pending'
    WHERE up.user_id = ? AND up.status = 'pending_verification'
    ORDER BY up.activated_at DESC
    LIMIT 1
  `).bind(userId).first().catch(() => null);

  const usedTrialRow = await db.prepare(`
    SELECT up.id as user_package_id, up.status, up.activated_at, up.expires_at,
           p.id as package_id, p.name, p.slug, p.price_ksh,
           COALESCE(p.duration_hours, 24) as duration_hours,
           COALESCE(p.is_free_trial, 0) as is_free_trial
    FROM user_packages up
    JOIN packages p ON up.package_id = p.id
    WHERE up.user_id = ? AND (COALESCE(p.is_free_trial, 0) = 1 OR p.slug = 'free-trial')
    ORDER BY up.activated_at DESC
    LIMIT 1
  `).bind(userId).first().catch(() => null);

  const isTrialActive = Boolean(
    activePackage && (
      activePackage.is_free_trial === 1 ||
      activePackage.slug === 'free-trial' ||
      activePackage.expires_at !== null
    )
  );
  const trialExpiresAt = (activePackage && activePackage.expires_at)
    ? activePackage.expires_at
    : (usedTrialRow?.expires_at || null);
  const trialSecondsRemaining = (activePackage && activePackage.expires_at)
    ? Math.max(0, activePackage.expires_at - now)
    : 0;
  const hasUsedFreeTrial = Boolean(usedTrialRow);
  const expiredTrialPackage = (!activePackage && usedTrialRow && usedTrialRow.status === 'expired')
    ? usedTrialRow
    : null;
  const isTrialExpiredLockout = Boolean(!activePackage && expiredTrialPackage);

  return {
    now,
    activePackage: activePackage || null,
    pendingPackage: pendingPackage || null,
    expiredTrialPackage,
    isTrialActive,
    trialExpiresAt,
    trialSecondsRemaining,
    hasUsedFreeTrial,
    isTrialExpiredLockout
  };
}

export const DEFAULT_RECAPTCHA_SITE_KEY = '6LfdzhouAAAAAPxDLqCVpSCr1rcPrW7a4lTcu-D-';
const DEFAULT_RECAPTCHA_SECRET_KEY = '6LfdzhouAAAAAJRNP6vfgi_QCLbd6q0-c73a6bi2';

/**
 * Verify Google reCAPTCHA token via Google's siteverify endpoint.
 */
export async function verifyRecaptchaToken(token, remoteIp = '', env = null) {
  const cleanToken = typeof token === 'string' ? token.trim() : '';
  if (!cleanToken) {
    return {
      ok: false,
      status: 400,
      error: 'Please complete the reCAPTCHA verification ("I am not a robot") before continuing.',
      codes: ['missing-input-response']
    };
  }

  const secret = (env && env.RECAPTCHA_SECRET_KEY) ? env.RECAPTCHA_SECRET_KEY : DEFAULT_RECAPTCHA_SECRET_KEY;
  const verifyFn = (env && typeof env.RECAPTCHA_VERIFY_FN === 'function') ? env.RECAPTCHA_VERIFY_FN : null;

  try {
    let data;
    if (verifyFn) {
      data = await verifyFn({ secret, response: cleanToken, remoteip: remoteIp });
    } else {
      const formBody = new URLSearchParams({
        secret,
        response: cleanToken
      });
      if (remoteIp && remoteIp !== 'default_ip') {
        formBody.set('remoteip', remoteIp);
      }

      const resp = await fetch('https://www.google.com/recaptcha/api/siteverify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: formBody.toString()
      });

      if (!resp.ok) {
        return {
          ok: false,
          status: 502,
          error: 'Could not reach Google reCAPTCHA verification service. Please try again.',
          codes: ['siteverify-http-error']
        };
      }
      data = await resp.json();
    }

    if (!data || data.success !== true) {
      return {
        ok: false,
        status: 403,
        error: 'reCAPTCHA verification failed or expired. Please complete the "I am not a robot" check again.',
        codes: Array.isArray(data?.['error-codes']) ? data['error-codes'] : ['invalid-input-response']
      };
    }

    if (typeof data.score === 'number' && data.score < 0.5) {
      return {
        ok: false,
        status: 403,
        error: 'Automated activity detected by reCAPTCHA. Please try again.',
        codes: ['low-score']
      };
    }

    return { ok: true, data };
  } catch (err) {
    console.error('reCAPTCHA verification error:', err);
    return {
      ok: false,
      status: 502,
      error: 'reCAPTCHA verification failed due to a network error. Please try again.',
      codes: ['verification-exception']
    };
  }
}
