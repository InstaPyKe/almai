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
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
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
           u.name, u.email, u.phone, u.role, u.status
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ? AND u.status = 'active'
    LIMIT 1
  `).bind(token, now).first();

  if (!session) return null;

  // Enforce sliding 2-minute session inactivity expiration (now + 120s)
  const refreshedExpiresAt = now + 120;
  env.DB.prepare('UPDATE sessions SET expires_at = ? WHERE id = ?').bind(refreshedExpiresAt, token).run().catch(() => {});

  return {
    token,
    id: session.user_id,
    name: session.name,
    email: session.email,
    phone: session.phone,
    role: session.role,
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

  if (auth.user.role !== 'admin') {
    return { errorResponse: jsonError('Forbidden: Administrator privileges required.', 403) };
  }
  return { user: auth.user };
}

/**
 * Rate Limiting for Authentication (3 attempts limit)
 */
export async function checkRateLimit(env, key) {
  if (!env || !env.DB) return { allowed: true, remaining: 3 };
  try {
    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB.prepare(`
      SELECT attempts, last_attempt, blocked_until 
      FROM rate_limits 
      WHERE key = ? 
      LIMIT 1
    `).bind(key).first();

    if (!row) return { allowed: true, remaining: 3, attempts: 0 };

    if (row.blocked_until && row.blocked_until > now) {
      const waitSeconds = row.blocked_until - now;
      return {
        allowed: false,
        remaining: 0,
        attempts: row.attempts,
        waitSeconds,
        waitMinutes: Math.ceil(waitSeconds / 60)
      };
    }

    // Reset if window of 10 minutes has passed
    if (now - row.last_attempt > 600) {
      await env.DB.prepare('DELETE FROM rate_limits WHERE key = ?').bind(key).run().catch(() => {});
      return { allowed: true, remaining: 3, attempts: 0 };
    }

    const remaining = Math.max(0, 3 - row.attempts);
    return {
      allowed: row.attempts < 3,
      remaining,
      attempts: row.attempts
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
    return { allowed: true, remaining: 3, attempts: 0 };
  }
}

export async function recordFailedAttempt(env, key, lockoutSeconds = 300) {
  if (!env || !env.DB) return { attempts: 1, remaining: 2, locked: false };
  try {
    const now = Math.floor(Date.now() / 1000);
    const row = await env.DB.prepare('SELECT attempts FROM rate_limits WHERE key = ?').bind(key).first();
    const currentAttempts = (row?.attempts || 0) + 1;
    const isLocked = currentAttempts >= 3;
    const blockedUntil = isLocked ? now + lockoutSeconds : 0;

    await env.DB.prepare(`
      INSERT INTO rate_limits (key, attempts, last_attempt, blocked_until)
      VALUES (?, ?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET
        attempts = excluded.attempts,
        last_attempt = excluded.last_attempt,
        blocked_until = CASE WHEN excluded.attempts >= 3 THEN ? ELSE rate_limits.blocked_until END
    `).bind(key, currentAttempts, now, blockedUntil, blockedUntil).run();

    return {
      attempts: currentAttempts,
      remaining: Math.max(0, 3 - currentAttempts),
      locked: isLocked,
      waitSeconds: lockoutSeconds,
      waitMinutes: Math.ceil(lockoutSeconds / 60)
    };
  } catch (err) {
    return { attempts: 1, remaining: 2, locked: false };
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
