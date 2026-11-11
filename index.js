var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// api/_utils.js
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}
__name(jsonResponse, "jsonResponse");
function jsonError(message, status = 400, details = null) {
  return jsonResponse({
    success: false,
    error: message,
    ...details ? { details } : {}
  }, status);
}
__name(jsonError, "jsonError");
function jsonSuccess(data = {}, status = 200, headers = {}) {
  return jsonResponse({
    success: true,
    ...data
  }, status, headers);
}
__name(jsonSuccess, "jsonSuccess");
function generateToken(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(generateToken, "generateToken");
function generateId(prefix = "id") {
  return `${prefix}_${generateToken(12)}`;
}
__name(generateId, "generateId");
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bufToHex, "bufToHex");
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
__name(hexToBuf, "hexToBuf");
async function hashPassword(password, saltHex = null) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return {
    hash: bufToHex(derivedBits),
    salt: bufToHex(salt)
  };
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}
__name(verifyPassword, "verifyPassword");
function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, value] = cookie.split("=");
    if (key === name) {
      return decodeURIComponent(value);
    }
  }
  return null;
}
__name(getCookie, "getCookie");
function getSessionToken(request) {
  const cookieToken = getCookie(request, "almai_session");
  if (cookieToken) return cookieToken;
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }
  return null;
}
__name(getSessionToken, "getSessionToken");
async function authenticate(request, env) {
  if (!env.DB) {
    throw new Error('Database binding "DB" is not configured in Cloudflare environment.');
  }
  const token = getSessionToken(request);
  if (!token) return null;
  const now = Math.floor(Date.now() / 1e3);
  const session = await env.DB.prepare(`
    SELECT s.id as session_id, s.user_id, s.expires_at, 
           u.name, u.email, u.phone, u.role, u.status, u.referral_code
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ? AND u.status = 'active'
    LIMIT 1
  `).bind(token, now).first();
  if (!session) return null;
  const refreshedExpiresAt = now + 7 * 86400;
  env.DB.prepare("UPDATE sessions SET expires_at = ? WHERE id = ?").bind(refreshedExpiresAt, token).run().catch(() => {
  });
  const effectiveRole = session.role === "admin" && session.email && session.email.toLowerCase() === "mentorbravin@gmail.com" ? "admin" : session.role === "admin" ? "user" : session.role;
  return {
    token,
    id: session.user_id,
    name: session.name,
    email: session.email,
    phone: session.phone,
    role: effectiveRole,
    referralCode: session.referral_code || "ALM" + session.user_id.replace(/[^a-zA-Z0-9]/g, "").substring(0, 6).toUpperCase(),
    status: session.status
  };
}
__name(authenticate, "authenticate");
async function requireAuth(request, env) {
  const user = await authenticate(request, env);
  if (!user) {
    return { errorResponse: jsonError("Session expired or authentication required. Please sign in.", 401) };
  }
  return { user };
}
__name(requireAuth, "requireAuth");
async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth;
  if (auth.user.role !== "admin" || !auth.user.email || auth.user.email.toLowerCase() !== "mentorbravin@gmail.com") {
    return { errorResponse: jsonError("Forbidden: Administrator privileges required.", 403) };
  }
  return { user: auth.user };
}
__name(requireAdmin, "requireAdmin");
async function checkRateLimit(env, key) {
  if (!env || !env.DB) return { allowed: true, remaining: 3, attempts: 0 };
  try {
    const now = Math.floor(Date.now() / 1e3);
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
        waitMinutes: Math.ceil(waitSeconds / 60),
        locked: true
      };
    }
    if (row.blocked_until && row.blocked_until <= now) {
      await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(key).run().catch(() => {
      });
      return { allowed: true, remaining: 3, attempts: 0, locked: false };
    }
    if (now - row.last_attempt > 600) {
      await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(key).run().catch(() => {
      });
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
    try {
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS rate_limits (
          key TEXT PRIMARY KEY,
          attempts INTEGER NOT NULL DEFAULT 1,
          last_attempt INTEGER NOT NULL,
          blocked_until INTEGER NOT NULL DEFAULT 0
        )
      `).run();
    } catch (e) {
    }
    return { allowed: true, remaining: 3, attempts: 0, locked: false };
  }
}
__name(checkRateLimit, "checkRateLimit");
async function recordFailedAttempt(env, key, lockoutSeconds = 300) {
  if (!env || !env.DB) return { attempts: 1, remaining: 2, locked: false, waitSeconds: 0 };
  try {
    const now = Math.floor(Date.now() / 1e3);
    const row = await env.DB.prepare("SELECT attempts, last_attempt, blocked_until FROM rate_limits WHERE key = ?").bind(key).first();
    let currentAttempts = 1;
    if (row) {
      if (row.blocked_until && row.blocked_until <= now || now - row.last_attempt > 600) {
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
    } catch (e) {
    }
    return { attempts: 1, remaining: 2, locked: false, waitSeconds: 0 };
  }
}
__name(recordFailedAttempt, "recordFailedAttempt");
async function clearRateLimit(env, key) {
  if (!env || !env.DB) return;
  try {
    await env.DB.prepare("DELETE FROM rate_limits WHERE key = ?").bind(key).run();
  } catch (err) {
  }
}
__name(clearRateLimit, "clearRateLimit");
async function createAuditLog(env, { adminId, action, targetType, targetId, details = {}, ip = "" }) {
  try {
    const id = generateId("aud");
    const now = Math.floor(Date.now() / 1e3);
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
    console.error("Audit log creation failed:", err);
  }
}
__name(createAuditLog, "createAuditLog");
async function awardReferralCommission(env, userId, packageId, packageName, packagePriceKsh) {
  if (!env || !env.DB || !userId || !packagePriceKsh) return null;
  try {
    const now = Math.floor(Date.now() / 1e3);
    const user = await env.DB.prepare("SELECT id, name, email, referred_by FROM users WHERE id = ?").bind(userId).first();
    if (!user || !user.referred_by) return null;
    if (user.referred_by === userId) return null;
    const referrer = await env.DB.prepare("SELECT id, name, email FROM users WHERE id = ?").bind(user.referred_by).first();
    if (!referrer) return null;
    const commissionKsh = Math.round(Number(packagePriceKsh) * 0.45);
    if (commissionKsh <= 0) return null;
    const existingRef = await env.DB.prepare("SELECT id, commission_paid FROM referrals WHERE referred_user_id = ? LIMIT 1").bind(userId).first();
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
      const refId = generateId("ref");
      await env.DB.prepare(`
        INSERT INTO referrals (id, referrer_id, referred_user_id, status, package_id, package_name, package_price_ksh, commission_rate, commission_amount_ksh, commission_paid, created_at, activated_at)
        VALUES (?, ?, ?, 'active_paid', ?, ?, ?, 0.45, ?, 1, ?, ?)
      `).bind(refId, referrer.id, userId, packageId, packageName, packagePriceKsh, commissionKsh, now, now).run();
    }
    let referrerWallet = await env.DB.prepare("SELECT id, available_balance_ksh, lifetime_earnings_ksh FROM wallets WHERE user_id = ?").bind(referrer.id).first();
    if (!referrerWallet) {
      const walId = generateId("wal");
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
    const txId = generateId("wtx");
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
    console.error("awardReferralCommission error:", err);
    return null;
  }
}
__name(awardReferralCommission, "awardReferralCommission");
var TRIAL_EXPIRED_LOCKOUT_MESSAGE = "Your 1-Day Free Trial has expired. Company services are locked until you upgrade to a paid partner package (Starter Pro, Exclusive, or Premium).";
var freeTrialSchemaReadyDbs = /* @__PURE__ */ new WeakSet();
async function ensureFreeTrialSchema(db) {
  if (!db || freeTrialSchemaReadyDbs.has(db)) return;
  await db.prepare("ALTER TABLE packages ADD COLUMN duration_hours INTEGER DEFAULT NULL").run().catch(() => {
  });
  await db.prepare("ALTER TABLE packages ADD COLUMN is_free_trial INTEGER NOT NULL DEFAULT 0").run().catch(() => {
  });
  const now = Math.floor(Date.now() / 1e3);
  await db.prepare(`
    INSERT OR IGNORE INTO packages (
      id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task,
      min_withdrawal_views_ksh, features, badge, is_active, created_at,
      duration_hours, is_free_trial
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, 24, 1)
  `).bind(
    "pkg_free_trial",
    "1-Day Free Trial",
    "free-trial",
    0,
    15,
    25,
    5e3,
    JSON.stringify([
      "Free 24-hour full partner access",
      "Earn KSh 15 per approved view",
      "Up to 25 views per WhatsApp task",
      "Full Paid Surveys & Creative access",
      "Upgrade anytime to keep earning permanently"
    ]),
    "FREE 1-DAY TRIAL",
    now
  ).run().catch(() => {
  });
  freeTrialSchemaReadyDbs.add(db);
}
__name(ensureFreeTrialSchema, "ensureFreeTrialSchema");
async function syncAndGetUserPackageState(db, userId, nowOverride = null) {
  await ensureFreeTrialSchema(db);
  const now = nowOverride !== null ? nowOverride : Math.floor(Date.now() / 1e3);
  await db.prepare(`
    UPDATE user_packages
    SET status = 'expired'
    WHERE user_id = ?
      AND status = 'active'
      AND expires_at IS NOT NULL
      AND expires_at <= ?
  `).bind(userId, now).run().catch(() => {
  });
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
    activePackage && (activePackage.is_free_trial === 1 || activePackage.slug === "free-trial" || activePackage.expires_at !== null)
  );
  const trialExpiresAt = activePackage && activePackage.expires_at ? activePackage.expires_at : usedTrialRow?.expires_at || null;
  const trialSecondsRemaining = activePackage && activePackage.expires_at ? Math.max(0, activePackage.expires_at - now) : 0;
  const hasUsedFreeTrial = Boolean(usedTrialRow);
  const expiredTrialPackage = !activePackage && usedTrialRow && usedTrialRow.status === "expired" ? usedTrialRow : null;
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
__name(syncAndGetUserPackageState, "syncAndGetUserPackageState");
var DEFAULT_RECAPTCHA_SECRET_KEY = "6LfdzhouAAAAAJRNP6vfgi_QCLbd6q0-c73a6bi2";
async function verifyRecaptchaToken(token, remoteIp = "", env = null) {
  const cleanToken = typeof token === "string" ? token.trim() : "";
  if (!cleanToken) {
    return {
      ok: false,
      status: 400,
      error: 'Please complete the reCAPTCHA verification ("I am not a robot") before continuing.',
      codes: ["missing-input-response"]
    };
  }
  const secret = env && env.RECAPTCHA_SECRET_KEY ? env.RECAPTCHA_SECRET_KEY : DEFAULT_RECAPTCHA_SECRET_KEY;
  const verifyFn = env && typeof env.RECAPTCHA_VERIFY_FN === "function" ? env.RECAPTCHA_VERIFY_FN : null;
  try {
    let data;
    if (verifyFn) {
      data = await verifyFn({ secret, response: cleanToken, remoteip: remoteIp });
    } else {
      const formBody = new URLSearchParams({
        secret,
        response: cleanToken
      });
      if (remoteIp && remoteIp !== "default_ip") {
        formBody.set("remoteip", remoteIp);
      }
      const resp = await fetch("https://www.google.com/recaptcha/api/siteverify", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: formBody.toString()
      });
      if (!resp.ok) {
        return {
          ok: false,
          status: 502,
          error: "Could not reach Google reCAPTCHA verification service. Please try again.",
          codes: ["siteverify-http-error"]
        };
      }
      data = await resp.json();
    }
    if (!data || data.success !== true) {
      return {
        ok: false,
        status: 403,
        error: 'reCAPTCHA verification failed or expired. Please complete the "I am not a robot" check again.',
        codes: Array.isArray(data?.["error-codes"]) ? data["error-codes"] : ["invalid-input-response"]
      };
    }
    if (typeof data.score === "number" && data.score < 0.5) {
      return {
        ok: false,
        status: 403,
        error: "Automated activity detected by reCAPTCHA. Please try again.",
        codes: ["low-score"]
      };
    }
    return { ok: true, data };
  } catch (err) {
    console.error("reCAPTCHA verification error:", err);
    return {
      ok: false,
      status: 502,
      error: "reCAPTCHA verification failed due to a network error. Please try again.",
      codes: ["verification-exception"]
    };
  }
}
__name(verifyRecaptchaToken, "verifyRecaptchaToken");

// api/admin/audit-logs.js
async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const { results } = await env.DB.prepare(`
      SELECT al.id, al.action, al.target_type, al.target_id, al.details, al.ip_address, al.created_at,
             u.name as admin_name, u.email as admin_email
      FROM admin_audit_logs al
      LEFT JOIN users u ON al.admin_id = u.id
      ORDER BY al.created_at DESC
      LIMIT 150
    `).all();
    const formatted = (results || []).map((row) => ({
      ...row,
      details: row.details ? typeof row.details === "string" ? JSON.parse(row.details) : row.details : null
    }));
    return jsonSuccess({
      auditLogs: formatted
    });
  } catch (err) {
    console.error("Audit logs fetch error:", err);
    return jsonError("Failed to fetch audit logs", 500);
  }
}
__name(onRequestGet, "onRequestGet");
async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const clearAllParam = url.searchParams.get("clearAll") === "true";
    let ids = [];
    let clearAll = clearAllParam;
    try {
      const text = await request.text();
      if (text && text.trim()) {
        const body = JSON.parse(text);
        if (Array.isArray(body?.ids)) ids = body.ids.filter(Boolean);
        if (body?.clearAll === true) clearAll = true;
      }
    } catch (e) {
    }
    if (clearAll) {
      const countRow = await env.DB.prepare("SELECT COUNT(*) as total FROM admin_audit_logs").first();
      const deletedCount2 = countRow?.total || 0;
      await env.DB.prepare("DELETE FROM admin_audit_logs").run();
      return jsonSuccess({
        message: `Cleared all ${deletedCount2} system audit logs.`,
        deletedCount: deletedCount2
      });
    }
    if (ids.length === 0) {
      return jsonError("Please select at least one audit log entry to clear", 400);
    }
    let deletedCount = 0;
    for (const logId of ids) {
      await env.DB.prepare("DELETE FROM admin_audit_logs WHERE id = ?").bind(logId).run();
      deletedCount++;
    }
    return jsonSuccess({
      message: `Cleared ${deletedCount} selected audit log entry(ies).`,
      deletedCount
    });
  } catch (err) {
    console.error("Audit logs delete error:", err);
    return jsonError("Failed to clear audit logs", 500);
  }
}
__name(onRequestDelete, "onRequestDelete");

// api/admin/bonuses.js
var VALID_BALANCE_TYPES = ["views", "referrals", "surveys"];
async function ensureBonusTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_regulations (
      id TEXT PRIMARY KEY,
      is_enabled INTEGER NOT NULL DEFAULT 1,
      min_bonus_ksh INTEGER NOT NULL DEFAULT 10,
      max_bonus_per_user_ksh INTEGER NOT NULL DEFAULT 5000,
      daily_budget_cap_ksh INTEGER NOT NULL DEFAULT 100000,
      cooldown_hours INTEGER NOT NULL DEFAULT 24,
      require_active_package INTEGER NOT NULL DEFAULT 1,
      default_balance_type TEXT NOT NULL DEFAULT 'views',
      updated_by TEXT,
      updated_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_distributions (
      id TEXT PRIMARY KEY,
      campaign_title TEXT NOT NULL,
      amount_per_user_ksh INTEGER NOT NULL,
      recipient_count INTEGER NOT NULL DEFAULT 0,
      total_disbursed_ksh INTEGER NOT NULL DEFAULT 0,
      balance_type TEXT NOT NULL DEFAULT 'views',
      eligibility_scope TEXT NOT NULL DEFAULT 'active_paid',
      package_filter_id TEXT,
      min_approved_views INTEGER NOT NULL DEFAULT 0,
      admin_id TEXT,
      created_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_recipient_logs (
      id TEXT PRIMARY KEY,
      distribution_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount_ksh INTEGER NOT NULL,
      balance_type TEXT NOT NULL DEFAULT 'views',
      created_at INTEGER NOT NULL
    )
  `).run();
  await db.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
  });
  const now = Math.floor(Date.now() / 1e3);
  await db.prepare(`
    INSERT OR IGNORE INTO bonus_regulations (
      id, is_enabled, min_bonus_ksh, max_bonus_per_user_ksh, daily_budget_cap_ksh,
      cooldown_hours, require_active_package, default_balance_type, updated_by, updated_at
    ) VALUES ('default', 1, 10, 5000, 100000, 24, 1, 'views', 'system', ?)
  `).bind(now).run();
}
__name(ensureBonusTables, "ensureBonusTables");
async function getRegulationsAndBudget(db) {
  const regulations = await db.prepare("SELECT * FROM bonus_regulations WHERE id = 'default' LIMIT 1").first();
  const now = Math.floor(Date.now() / 1e3);
  const since24h = now - 86400;
  const dailyRow = await db.prepare(`
    SELECT COALESCE(SUM(total_disbursed_ksh), 0) as disbursed_24h
    FROM bonus_distributions
    WHERE created_at >= ?
  `).bind(since24h).first();
  const allTimeRow = await db.prepare(`
    SELECT
      COALESCE(SUM(total_disbursed_ksh), 0) as total_disbursed,
      COALESCE(SUM(recipient_count), 0) as total_recipients
    FROM bonus_distributions
  `).first();
  const todayDisbursedKsh = dailyRow?.disbursed_24h || 0;
  const dailyBudgetCapKsh = regulations?.daily_budget_cap_ksh || 1e5;
  return {
    regulations,
    budgetStats: {
      todayDisbursedKsh,
      dailyBudgetCapKsh,
      remainingDailyBudgetKsh: Math.max(0, dailyBudgetCapKsh - todayDisbursedKsh),
      totalAllTimeBonusKsh: allTimeRow?.total_disbursed || 0,
      totalBonusRecipientsCount: allTimeRow?.total_recipients || 0
    }
  };
}
__name(getRegulationsAndBudget, "getRegulationsAndBudget");
async function resolveEligibleActiveUsers(db, regulations, params) {
  const scope = params.scope || "active_paid";
  const packageId = params.packageId && params.packageId !== "all" ? String(params.packageId).trim() : "";
  const minApprovedViews = Math.max(0, parseInt(params.minApprovedViews, 10) || 0);
  const selectedIds = Array.isArray(params.userIds) ? params.userIds.filter(Boolean) : [];
  let blockedReason = null;
  if (scope === "all_active" && regulations.require_active_package === 1) {
    blockedReason = 'Current Bonus Regulation requires an Active Paid Package. Either target "Active Paid Partners" or disable "Require Active Package" in Regulations first.';
  }
  const { results: candidateRows } = await db.prepare(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.phone,
      (
        SELECT up.package_id
        FROM user_packages up
        WHERE up.user_id = u.id AND up.status = 'active'
        ORDER BY up.activated_at DESC
        LIMIT 1
      ) as active_package_id,
      (
        SELECT p.name
        FROM user_packages up
        JOIN packages p ON up.package_id = p.id
        WHERE up.user_id = u.id AND up.status = 'active'
        ORDER BY up.activated_at DESC
        LIMIT 1
      ) as active_package_name,
      COALESCE((
        SELECT SUM(CASE WHEN ts.status = 'approved' THEN ts.approved_views ELSE 0 END)
        FROM task_submissions ts
        WHERE ts.user_id = u.id
      ), 0) as total_approved_views
    FROM users u
    WHERE u.status = 'active' AND u.role != 'admin'
  `).all();
  const candidates = (candidateRows || []).filter((u) => {
    if (scope === "selected") {
      if (!selectedIds.includes(u.id)) return false;
      if (regulations.require_active_package === 1 && !u.active_package_id) return false;
    } else if (scope === "active_paid") {
      if (!u.active_package_id) return false;
    }
    if (packageId && u.active_package_id !== packageId) return false;
    if ((u.total_approved_views || 0) < minApprovedViews) return false;
    return true;
  });
  const cooldownHours = Math.max(0, Number(regulations.cooldown_hours || 0));
  const now = Math.floor(Date.now() / 1e3);
  const cooldownCutoff = now - cooldownHours * 3600;
  let recentlyRewardedSet = /* @__PURE__ */ new Set();
  if (cooldownHours > 0 && candidates.length > 0) {
    const { results: recentLogs } = await db.prepare(`
      SELECT DISTINCT user_id
      FROM bonus_recipient_logs
      WHERE created_at >= ?
    `).bind(cooldownCutoff).all();
    for (const r of recentLogs || []) {
      recentlyRewardedSet.add(r.user_id);
    }
  }
  const eligibleUsers = [];
  let cooldownSkippedCount = 0;
  for (const u of candidates) {
    if (cooldownHours > 0 && recentlyRewardedSet.has(u.id)) {
      cooldownSkippedCount++;
    } else {
      eligibleUsers.push(u);
    }
  }
  return {
    eligibleUsers,
    matchedBeforeCooldown: candidates.length,
    cooldownSkippedCount,
    blockedReason
  };
}
__name(resolveEligibleActiveUsers, "resolveEligibleActiveUsers");
async function onRequestGet2(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    await ensureBonusTables(env.DB);
    const { regulations, budgetStats } = await getRegulationsAndBudget(env.DB);
    const activeRegRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'active' AND role != 'admin'").first();
    const activePaidRow = await env.DB.prepare(`
      SELECT COUNT(DISTINCT u.id) as c
      FROM users u
      JOIN user_packages up ON up.user_id = u.id
      WHERE u.status = 'active' AND u.role != 'admin' AND up.status = 'active'
    `).first();
    const { results: packages } = await env.DB.prepare("SELECT id, name, slug FROM packages ORDER BY price_ksh ASC").all();
    const { results: recentDistributions } = await env.DB.prepare(`
      SELECT
        bd.id, bd.campaign_title, bd.amount_per_user_ksh, bd.recipient_count,
        bd.total_disbursed_ksh, bd.balance_type, bd.eligibility_scope,
        bd.package_filter_id, bd.min_approved_views, bd.created_at,
        u.name as admin_name
      FROM bonus_distributions bd
      LEFT JOIN users u ON bd.admin_id = u.id
      ORDER BY bd.created_at DESC
      LIMIT 20
    `).all();
    return jsonSuccess({
      regulations,
      budgetStats,
      activeSummary: {
        activeRegisteredCount: activeRegRow?.c || 0,
        activePaidCount: activePaidRow?.c || 0
      },
      packages: packages || [],
      recentDistributions: recentDistributions || []
    });
  } catch (err) {
    console.error("Admin bonuses GET error:", err);
    return jsonError("Failed to load active user bonus configuration", 500);
  }
}
__name(onRequestGet2, "onRequestGet");
async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  const ip = request.headers.get("cf-connecting-ip") || "";
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const action = body.action || "distribute";
  try {
    await ensureBonusTables(env.DB);
    const now = Math.floor(Date.now() / 1e3);
    if (action === "save_regulations") {
      const isEnabled = body.isEnabled === false || body.isEnabled === 0 ? 0 : 1;
      const minBonusKsh = parseInt(body.minBonusKsh, 10);
      const maxBonusPerUserKsh = parseInt(body.maxBonusPerUserKsh, 10);
      const dailyBudgetCapKsh = parseInt(body.dailyBudgetCapKsh, 10);
      const cooldownHours = parseInt(body.cooldownHours, 10);
      const requireActivePackage = body.requireActivePackage === false || body.requireActivePackage === 0 ? 0 : 1;
      const defaultBalanceType = VALID_BALANCE_TYPES.includes(body.defaultBalanceType) ? body.defaultBalanceType : "views";
      if (isNaN(minBonusKsh) || minBonusKsh < 1) {
        return jsonError("Minimum bonus must be at least KSh 1", 400);
      }
      if (isNaN(maxBonusPerUserKsh) || maxBonusPerUserKsh < minBonusKsh) {
        return jsonError("Maximum bonus per user must be greater than or equal to minimum bonus", 400);
      }
      if (isNaN(dailyBudgetCapKsh) || dailyBudgetCapKsh < maxBonusPerUserKsh) {
        return jsonError("Daily budget cap must be at least the maximum single user bonus", 400);
      }
      if (isNaN(cooldownHours) || cooldownHours < 0 || cooldownHours > 8760) {
        return jsonError("Cooldown hours must be between 0 and 8,760 hours (1 year)", 400);
      }
      await env.DB.prepare(`
        UPDATE bonus_regulations
        SET is_enabled = ?,
            min_bonus_ksh = ?,
            max_bonus_per_user_ksh = ?,
            daily_budget_cap_ksh = ?,
            cooldown_hours = ?,
            require_active_package = ?,
            default_balance_type = ?,
            updated_by = ?,
            updated_at = ?
        WHERE id = 'default'
      `).bind(
        isEnabled,
        minBonusKsh,
        maxBonusPerUserKsh,
        dailyBudgetCapKsh,
        cooldownHours,
        requireActivePackage,
        defaultBalanceType,
        admin.id,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "UPDATE_BONUS_REGULATIONS",
        targetType: "bonus_regulations",
        targetId: "default",
        details: {
          isEnabled,
          minBonusKsh,
          maxBonusPerUserKsh,
          dailyBudgetCapKsh,
          cooldownHours,
          requireActivePackage,
          defaultBalanceType
        },
        ip
      });
      const refreshed2 = await getRegulationsAndBudget(env.DB);
      return jsonSuccess({
        message: "Bonus regulation policy saved successfully.",
        ...refreshed2
      });
    }
    const { regulations, budgetStats } = await getRegulationsAndBudget(env.DB);
    const amountPerUserKsh = parseInt(body.amountPerUserKsh ?? body.amountKsh, 10) || 0;
    const scope = body.scope || "active_paid";
    const balanceType = VALID_BALANCE_TYPES.includes(body.balanceType) ? body.balanceType : regulations.default_balance_type || "views";
    const { eligibleUsers, matchedBeforeCooldown, cooldownSkippedCount, blockedReason } = await resolveEligibleActiveUsers(env.DB, regulations, {
      scope,
      packageId: body.packageId,
      minApprovedViews: body.minApprovedViews,
      userIds: body.userIds
    });
    const totalDisbursedKsh = Math.max(0, amountPerUserKsh) * eligibleUsers.length;
    let regulationViolation = blockedReason;
    if (!regulationViolation && regulations.is_enabled !== 1) {
      regulationViolation = "Active User Bonus payouts are currently paused by admin regulation settings.";
    } else if (!regulationViolation && (amountPerUserKsh < regulations.min_bonus_ksh || amountPerUserKsh > regulations.max_bonus_per_user_ksh)) {
      regulationViolation = `Specified bonus (KSh ${amountPerUserKsh.toLocaleString()}) violates admin regulation range: KSh ${regulations.min_bonus_ksh.toLocaleString()} \u2013 KSh ${regulations.max_bonus_per_user_ksh.toLocaleString()}.`;
    } else if (!regulationViolation && totalDisbursedKsh > budgetStats.remainingDailyBudgetKsh) {
      regulationViolation = `Total payout (KSh ${totalDisbursedKsh.toLocaleString()}) exceeds remaining regulated 24h budget cap of KSh ${budgetStats.remainingDailyBudgetKsh.toLocaleString()}.`;
    }
    if (action === "preview") {
      return jsonSuccess({
        preview: {
          eligibleCount: eligibleUsers.length,
          matchedBeforeCooldown,
          cooldownSkippedCount,
          amountPerUserKsh,
          totalDisbursedKsh,
          balanceType,
          remainingDailyBudgetKsh: budgetStats.remainingDailyBudgetKsh,
          regulationViolation
        }
      });
    }
    if (action !== "distribute") {
      return jsonError(`Unsupported bonus action "${action}"`, 400);
    }
    const campaignTitle = (body.campaignTitle || body.reason || "Active Partner Appreciation Bonus").trim().slice(0, 120);
    if (!campaignTitle) {
      return jsonError("Please provide a bonus campaign title or reason", 400);
    }
    if (regulationViolation) {
      return jsonError(regulationViolation, 400);
    }
    if (eligibleUsers.length === 0) {
      const cooldownHint = cooldownSkippedCount > 0 ? ` (${cooldownSkippedCount} active user(s) were skipped because they already received a bonus within the ${regulations.cooldown_hours}h cooldown regulation.)` : "";
      return jsonError(`No eligible active users matched the selected criteria.${cooldownHint}`, 400);
    }
    const distributionId = generateId("bon");
    await env.DB.prepare(`
      INSERT INTO bonus_distributions (
        id, campaign_title, amount_per_user_ksh, recipient_count, total_disbursed_ksh,
        balance_type, eligibility_scope, package_filter_id, min_approved_views, admin_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      distributionId,
      campaignTitle,
      amountPerUserKsh,
      eligibleUsers.length,
      totalDisbursedKsh,
      balanceType,
      scope,
      body.packageId && body.packageId !== "all" ? String(body.packageId) : null,
      Math.max(0, parseInt(body.minApprovedViews, 10) || 0),
      admin.id,
      now
    ).run();
    for (const u of eligibleUsers) {
      let wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(u.id).first();
      if (!wallet) {
        const walletId = generateId("wal");
        await env.DB.prepare(`
          INSERT INTO wallets (
            id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh,
            surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at
          ) VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, u.id, now).run().catch(() => {
        });
        wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(u.id).first();
      }
      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curSurveys = wallet?.surveys_balance_ksh || 0;
      const curViews = (wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef + curSurveys ? curAvail - curRef - curSurveys : wallet?.views_balance_ksh || 0;
      const nextViews = balanceType === "views" ? curViews + amountPerUserKsh : curViews;
      const nextRef = balanceType === "referrals" ? curRef + amountPerUserKsh : curRef;
      const nextSurveys = balanceType === "surveys" ? curSurveys + amountPerUserKsh : curSurveys;
      const nextAvail = nextViews + nextRef + nextSurveys;
      const nextLifetime = (wallet?.lifetime_earnings_ksh || 0) + amountPerUserKsh;
      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            referrals_balance_ksh = ?,
            surveys_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViews, nextRef, nextSurveys, nextAvail, nextLifetime, now, u.id).run();
      const txId = generateId("tx_bon");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        u.id,
        amountPerUserKsh,
        nextAvail,
        distributionId,
        `Active User Bonus (${campaignTitle}): +KSh ${amountPerUserKsh.toLocaleString()} to ${balanceType}`,
        now
      ).run();
      const logId = generateId("brl");
      await env.DB.prepare(`
        INSERT INTO bonus_recipient_logs (id, distribution_id, user_id, amount_ksh, balance_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(logId, distributionId, u.id, amountPerUserKsh, balanceType, now).run();
    }
    await createAuditLog(env, {
      adminId: admin.id,
      action: "DISTRIBUTE_ACTIVE_BONUS",
      targetType: "bonus_distribution",
      targetId: distributionId,
      details: {
        campaignTitle,
        amountPerUserKsh,
        recipientCount: eligibleUsers.length,
        cooldownSkippedCount,
        totalDisbursedKsh,
        balanceType,
        scope
      },
      ip
    });
    const refreshed = await getRegulationsAndBudget(env.DB);
    return jsonSuccess({
      message: `Awarded KSh ${amountPerUserKsh.toLocaleString()} bonus (${campaignTitle}) to ${eligibleUsers.length} active partner(s) \u2014 total KSh ${totalDisbursedKsh.toLocaleString()}!`,
      distribution: {
        id: distributionId,
        campaignTitle,
        amountPerUserKsh,
        recipientCount: eligibleUsers.length,
        cooldownSkippedCount,
        totalDisbursedKsh,
        balanceType
      },
      ...refreshed
    });
  } catch (err) {
    console.error("Admin bonuses POST error:", err);
    return jsonError("Failed to process regulated active user bonus", 500);
  }
}
__name(onRequestPost, "onRequestPost");

// api/admin/cleanup.js
async function onRequestGet3(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const now = Math.floor(Date.now() / 1e3);
  try {
    const expiredSessions = await env.DB.prepare("SELECT COUNT(*) as c FROM sessions WHERE expires_at < ?").bind(now).first().catch(() => ({ c: 0 }));
    const failedPayments = await env.DB.prepare("SELECT COUNT(*) as c FROM payment_transactions WHERE status IN ('failed', 'rejected')").first().catch(() => ({ c: 0 }));
    const rejectedTasks = await env.DB.prepare("SELECT COUNT(*) as c FROM task_submissions WHERE status = 'rejected'").first().catch(() => ({ c: 0 }));
    const rejectedWithdrawals = await env.DB.prepare("SELECT COUNT(*) as c FROM withdrawal_requests WHERE status = 'rejected'").first().catch(() => ({ c: 0 }));
    const auditLogs = await env.DB.prepare("SELECT COUNT(*) as c FROM admin_audit_logs").first().catch(() => ({ c: 0 }));
    const orphanedEvidence = await env.DB.prepare(`
      SELECT COUNT(*) as c FROM task_evidence te
      WHERE NOT EXISTS (SELECT 1 FROM task_submissions ts WHERE ts.evidence_id = te.id)
    `).first().catch(() => ({ c: 0 }));
    const suspendedUsers = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'suspended' AND role != 'admin'").first().catch(() => ({ c: 0 }));
    return jsonSuccess({
      junkCounts: {
        expiredSessions: expiredSessions?.c || 0,
        failedPayments: failedPayments?.c || 0,
        rejectedTasks: rejectedTasks?.c || 0,
        rejectedWithdrawals: rejectedWithdrawals?.c || 0,
        auditLogs: auditLogs?.c || 0,
        orphanedEvidence: orphanedEvidence?.c || 0,
        suspendedUsers: suspendedUsers?.c || 0
      }
    });
  } catch (err) {
    console.error("Cleanup counts error:", err);
    return jsonError("Failed to inspect junk system counts", 500);
  }
}
__name(onRequestGet3, "onRequestGet");
async function onRequestPost2(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const targets = Array.isArray(body.targets) ? body.targets : [];
  const paymentIds = Array.isArray(body.paymentIds) ? body.paymentIds.filter(Boolean) : [];
  const taskIds = Array.isArray(body.taskIds) ? body.taskIds.filter(Boolean) : [];
  const withdrawalIds = Array.isArray(body.withdrawalIds) ? body.withdrawalIds.filter(Boolean) : [];
  if (targets.length === 0 && paymentIds.length === 0 && taskIds.length === 0 && withdrawalIds.length === 0) {
    return jsonError("Please select at least one junk category or record to clear", 400);
  }
  const now = Math.floor(Date.now() / 1e3);
  const ip = request.headers.get("cf-connecting-ip") || "";
  const breakdown = {};
  let totalDeleted = 0;
  try {
    if (targets.includes("expired_sessions")) {
      const res = await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now).run();
      const count = res?.meta?.changes || 0;
      breakdown.expiredSessions = count;
      totalDeleted += count;
    }
    if (targets.includes("failed_payments")) {
      const res = await env.DB.prepare("DELETE FROM payment_transactions WHERE status IN ('failed', 'rejected')").run();
      const count = res?.meta?.changes || 0;
      breakdown.failedPayments = count;
      totalDeleted += count;
    }
    if (targets.includes("rejected_tasks")) {
      const res = await env.DB.prepare("DELETE FROM task_submissions WHERE status = 'rejected'").run();
      const count = res?.meta?.changes || 0;
      breakdown.rejectedTasks = count;
      totalDeleted += count;
    }
    if (targets.includes("orphaned_evidence")) {
      const res = await env.DB.prepare(`
        DELETE FROM task_evidence
        WHERE NOT EXISTS (SELECT 1 FROM task_submissions ts WHERE ts.evidence_id = task_evidence.id)
      `).run();
      const count = res?.meta?.changes || 0;
      breakdown.orphanedEvidence = count;
      totalDeleted += count;
    }
    if (targets.includes("rejected_withdrawals")) {
      const res = await env.DB.prepare("DELETE FROM withdrawal_requests WHERE status = 'rejected'").run();
      const count = res?.meta?.changes || 0;
      breakdown.rejectedWithdrawals = count;
      totalDeleted += count;
    }
    if (targets.includes("all_audit_logs")) {
      const res = await env.DB.prepare("DELETE FROM admin_audit_logs").run();
      const count = res?.meta?.changes || 0;
      breakdown.auditLogs = count;
      totalDeleted += count;
    } else if (targets.includes("old_audit_logs")) {
      const sevenDaysAgo = now - 7 * 86400;
      const res = await env.DB.prepare("DELETE FROM admin_audit_logs WHERE created_at < ?").bind(sevenDaysAgo).run();
      const count = res?.meta?.changes || 0;
      breakdown.oldAuditLogs = count;
      totalDeleted += count;
    }
    if (paymentIds.length > 0) {
      let c = 0;
      for (const id of paymentIds) {
        const res = await env.DB.prepare("DELETE FROM payment_transactions WHERE id = ?").bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedPayments = c;
      totalDeleted += c;
    }
    if (taskIds.length > 0) {
      let c = 0;
      for (const id of taskIds) {
        const res = await env.DB.prepare("DELETE FROM task_submissions WHERE id = ?").bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedTasks = c;
      totalDeleted += c;
    }
    if (withdrawalIds.length > 0) {
      let c = 0;
      for (const id of withdrawalIds) {
        const res = await env.DB.prepare("DELETE FROM withdrawal_requests WHERE id = ? AND status != 'pending'").bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedWithdrawals = c;
      totalDeleted += c;
    }
    if (!targets.includes("all_audit_logs")) {
      await createAuditLog(env, {
        adminId: admin.id,
        action: "SYSTEM_JUNK_CLEANUP",
        targetType: "system",
        targetId: "cleanup",
        details: { targets, breakdown, totalDeleted },
        ip
      });
    }
    return jsonSuccess({
      message: `System cleanup complete: cleared ${totalDeleted} junk record(s).`,
      totalDeleted,
      breakdown
    });
  } catch (err) {
    console.error("System cleanup error:", err);
    return jsonError("Failed to execute system junk cleanup", 500);
  }
}
__name(onRequestPost2, "onRequestPost");

// api/admin/packages.js
async function onRequestGet4(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    await ensureFreeTrialSchema(env.DB);
    const { results } = await env.DB.prepare("SELECT * FROM packages ORDER BY price_ksh ASC").all();
    return jsonSuccess({ packages: results || [] });
  } catch (err) {
    return jsonError("Failed to fetch packages for admin", 500);
  }
}
__name(onRequestGet4, "onRequestGet");
async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { id, name, priceKsh, rewardPerViewKsh, maxViewsPerTask, minWithdrawalViewsKsh, isActive, features, badge, durationHours, isFreeTrial } = body;
  if (!id) {
    return jsonError("Package ID is required", 400);
  }
  try {
    await ensureFreeTrialSchema(env.DB);
    const existing = await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(id).first();
    if (!existing) {
      return jsonError("Package not found", 404);
    }
    const price = priceKsh !== void 0 ? parseInt(priceKsh, 10) : existing.price_ksh;
    const reward = rewardPerViewKsh !== void 0 ? parseInt(rewardPerViewKsh, 10) : existing.reward_per_view_ksh;
    const maxViews = maxViewsPerTask !== void 0 ? parseInt(maxViewsPerTask, 10) : existing.max_views_per_task;
    const minWithdrawal = minWithdrawalViewsKsh !== void 0 ? parseInt(minWithdrawalViewsKsh, 10) : existing.min_withdrawal_views_ksh || 5e3;
    const active = isActive !== void 0 ? isActive ? 1 : 0 : existing.is_active;
    const pkgName = name || existing.name;
    const pkgBadge = badge !== void 0 ? badge : existing.badge;
    const pkgFeatures = features ? typeof features === "string" ? features : JSON.stringify(features) : existing.features;
    const nextDurationHours = durationHours !== void 0 ? durationHours === null || durationHours === "" ? null : Math.max(1, parseInt(durationHours, 10)) : existing.duration_hours ?? null;
    const nextIsFreeTrial = isFreeTrial !== void 0 ? isFreeTrial ? 1 : 0 : existing.is_free_trial ?? 0;
    await env.DB.prepare(`
      UPDATE packages
      SET name = ?, price_ksh = ?, reward_per_view_ksh = ?, max_views_per_task = ?,
          min_withdrawal_views_ksh = ?, is_active = ?, badge = ?, features = ?,
          duration_hours = ?, is_free_trial = ?
      WHERE id = ?
    `).bind(pkgName, price, reward, maxViews, minWithdrawal, active, pkgBadge, pkgFeatures, nextDurationHours, nextIsFreeTrial, id).run();
    await createAuditLog(env, {
      adminId: admin.id,
      action: "UPDATE_PACKAGE",
      targetType: "package",
      targetId: id,
      details: { name: pkgName, price, reward, maxViews, minWithdrawalViews: minWithdrawal, active, durationHours: nextDurationHours, isFreeTrial: nextIsFreeTrial }
    });
    return jsonSuccess({
      message: "Package updated successfully",
      package: {
        id,
        name: pkgName,
        price_ksh: price,
        reward_per_view_ksh: reward,
        max_views_per_task: maxViews,
        min_withdrawal_views_ksh: minWithdrawal,
        is_active: active,
        duration_hours: nextDurationHours,
        is_free_trial: nextIsFreeTrial
      }
    });
  } catch (err) {
    console.error("Update package error:", err);
    return jsonError("Failed to update package", 500);
  }
}
__name(onRequestPut, "onRequestPut");

// api/admin/payments.js
async function onRequestGet5(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT pt.id, pt.user_id, pt.package_id, pt.amount_ksh, pt.phone_number,
             pt.mpesa_receipt_number, pt.status, pt.notes, pt.verified_at, pt.created_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone,
             p.name as package_name, p.slug as package_slug, p.reward_per_view_ksh
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
    `;
    if (filterStatus === "pending") {
      query += ` WHERE pt.status = 'pending' ORDER BY pt.created_at ASC LIMIT 100`;
    } else if (filterStatus === "completed") {
      query += ` WHERE pt.status = 'completed' ORDER BY pt.created_at DESC LIMIT 100`;
    } else {
      query += ` ORDER BY pt.created_at DESC LIMIT 150`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      payments: results || []
    });
  } catch (err) {
    console.error("Admin fetch payments error:", err);
    return jsonError("Failed to fetch payment transactions for verification", 500);
  }
}
__name(onRequestGet5, "onRequestGet");
async function onRequestPost3(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { paymentId, action, notes } = body;
  if (!paymentId || !action) {
    return jsonError('paymentId and action ("verify" | "reject") are required', 400);
  }
  try {
    await ensureFreeTrialSchema(env.DB);
    const payment = await env.DB.prepare(`
      SELECT pt.*, u.name as user_name, u.email as user_email, p.name as package_name, p.duration_hours
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
      WHERE pt.id = ?
      LIMIT 1
    `).bind(paymentId).first();
    if (!payment) {
      return jsonError("Payment transaction not found", 404);
    }
    if (payment.status !== "pending") {
      return jsonError(`This payment transaction is already marked as ${payment.status}`, 409);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "verify") {
      const adminNote = notes || `Verified by Admin ${admin.name}`;
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'completed',
            verified_at = ?,
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(now, adminNote, payment.id).run();
      await env.DB.prepare(`
        UPDATE user_packages
        SET status = 'expired'
        WHERE user_id = ? AND status = 'active'
      `).bind(payment.user_id).run();
      const userPackageId = generateId("upkg");
      const newExpiresAt = payment.duration_hours && payment.duration_hours > 0 ? now + payment.duration_hours * 3600 : null;
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at, expires_at)
        VALUES (?, ?, ?, 'active', ?, ?)
      `).bind(userPackageId, payment.user_id, payment.package_id, now, newExpiresAt).run();
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND id != ?
      `).bind(payment.user_id, userPackageId).run();
      const referralResult = await awardReferralCommission(env, payment.user_id, payment.package_id, payment.package_name, payment.amount_ksh);
      await createAuditLog(env, {
        adminId: admin.id,
        action: "VERIFY_PAYMENT_CODE",
        targetType: "payment_transaction",
        targetId: payment.id,
        details: {
          code: payment.mpesa_receipt_number,
          amountKsh: payment.amount_ksh,
          userId: payment.user_id,
          userName: payment.user_name,
          packageId: payment.package_id,
          packageName: payment.package_name
        },
        ip
      });
      return jsonSuccess({
        message: `M-Pesa code ${payment.mpesa_receipt_number} verified! ${payment.package_name} activated for ${payment.user_name}.`,
        payment: {
          id: payment.id,
          status: "completed",
          mpesaReceipt: payment.mpesa_receipt_number
        }
      });
    } else if (action === "reject") {
      const rejectReason = notes || "M-Pesa transaction reference could not be verified with Safaricom";
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'failed',
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, payment.id).run();
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND package_id = ?
      `).bind(payment.user_id, payment.package_id).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_PAYMENT_CODE",
        targetType: "payment_transaction",
        targetId: payment.id,
        details: {
          code: payment.mpesa_receipt_number,
          reason: rejectReason,
          userId: payment.user_id,
          userName: payment.user_name
        },
        ip
      });
      return jsonSuccess({
        message: `Transaction code ${payment.mpesa_receipt_number} has been rejected.`,
        payment: {
          id: payment.id,
          status: "failed",
          reason: rejectReason
        }
      });
    } else {
      return jsonError('Invalid action specified. Must be "verify" or "reject".', 400);
    }
  } catch (err) {
    console.error("Verify payment error:", err);
    return jsonError("Failed to process payment verification. Please try again.", 500);
  }
}
__name(onRequestPost3, "onRequestPost");

// api/admin/products-posts.js
async function onRequestGet6(context) {
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
      posts: results || [],
      productPosts: results || []
    });
  } catch (err) {
    console.error("Admin fetch product posts error:", err);
    return jsonError("Failed to fetch product posts for admin", 500);
  }
}
__name(onRequestGet6, "onRequestGet");
async function onRequestPost4(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { title, brandName, description, caption, imageBase64, imageName } = body;
  if (!title || typeof title !== "string" || title.trim().length < 3) {
    return jsonError("Please enter a valid product title (at least 3 characters)", 400);
  }
  if (!brandName || typeof brandName !== "string" || brandName.trim().length < 2) {
    return jsonError("Please enter a valid brand or company name", 400);
  }
  if (!caption || typeof caption !== "string" || caption.trim().length < 5) {
    return jsonError("Please provide the suggested WhatsApp caption for users to copy", 400);
  }
  if (!imageBase64 || typeof imageBase64 !== "string") {
    return jsonError("Product picture image file is required", 400);
  }
  if (imageBase64.length > 5 * 1024 * 1024) {
    return jsonError("Product image file is too large. Please upload an image under 3.5MB.", 400);
  }
  try {
    const postId = generateId("prod");
    const now = Math.floor(Date.now() / 1e3);
    const cleanTitle = title.trim();
    const cleanBrand = brandName.trim();
    const cleanDesc = (description || "").trim();
    const cleanCaption = caption.trim();
    const fileName = imageName || "whatsapp_promo.png";
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
    const ip = request.headers.get("cf-connecting-ip") || "";
    await createAuditLog(env, {
      adminId: admin.id,
      action: "POST_WHATSAPP_PRODUCT",
      targetType: "product_post",
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
    console.error("Admin post product creative error:", err);
    return jsonError("Failed to publish product creative. Please try again.", 500);
  }
}
__name(onRequestPost4, "onRequestPost");
async function onRequestDelete2(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  const url = new URL(request.url);
  let isClearAll = url.searchParams.get("clearAll") === "true" || url.searchParams.get("action") === "clear_all";
  let postId = url.searchParams.get("id") || url.searchParams.get("postId");
  let postIds = null;
  if (!postId && !isClearAll) {
    try {
      const text = await request.text();
      if (text && text.trim().length > 0) {
        const body = JSON.parse(text);
        postId = body?.postId || body?.id;
        if (Array.isArray(body?.postIds)) {
          postIds = body.postIds.filter(Boolean);
        }
        if (body?.action === "clear_all" || body?.clearAll === true) {
          isClearAll = true;
        }
      }
    } catch (e) {
    }
  }
  if (isClearAll) {
    return await handleClearAll(env, admin, request);
  }
  if (Array.isArray(postIds) && postIds.length > 0) {
    try {
      let deletedCount = 0;
      for (const pid of postIds) {
        await env.DB.prepare("DELETE FROM product_posts WHERE id = ?").bind(pid).run();
        await env.DB.prepare("DELETE FROM campaigns WHERE id = ?").bind(`camp_${pid}`).run();
        deletedCount++;
      }
      const ip = request.headers.get("cf-connecting-ip") || "";
      await createAuditLog(env, {
        adminId: admin.id,
        action: "BULK_DELETE_PRODUCTS",
        targetType: "product_posts",
        targetId: "bulk",
        details: { deletedCount, postIds },
        ip
      });
      return jsonSuccess({
        message: `Successfully deleted ${deletedCount} selected product creative(s).`,
        deletedCount
      });
    } catch (err) {
      console.error("Bulk delete products error:", err);
      return jsonError("Failed to delete selected products", 500);
    }
  }
  if (!postId) {
    return jsonError("Product ID, postIds array, or clearAll parameter is required", 400);
  }
  try {
    const existing = await env.DB.prepare("SELECT id, title FROM product_posts WHERE id = ?").bind(postId).first();
    if (!existing) {
      return jsonError("Product post not found or already deleted", 404);
    }
    await env.DB.prepare("DELETE FROM product_posts WHERE id = ?").bind(postId).run();
    const campaignId = `camp_${postId}`;
    await env.DB.prepare("DELETE FROM campaigns WHERE id = ?").bind(campaignId).run();
    const ip = request.headers.get("cf-connecting-ip") || "";
    await createAuditLog(env, {
      adminId: admin.id,
      action: "DELETE_PRODUCT_POST",
      targetType: "product_post",
      targetId: postId,
      details: { title: existing.title },
      ip
    });
    return jsonSuccess({
      message: `Product creative "${existing.title}" has been deleted successfully.`
    });
  } catch (err) {
    console.error("Delete product post error:", err);
    return jsonError("Failed to delete product post", 500);
  }
}
__name(onRequestDelete2, "onRequestDelete");
async function handleClearAll(env, admin, request) {
  try {
    const countRow = await env.DB.prepare("SELECT count(*) as total FROM product_posts").first();
    const count = countRow?.total || 0;
    await env.DB.prepare("DELETE FROM product_posts").run();
    await env.DB.prepare("DELETE FROM campaigns WHERE id LIKE 'camp_%'").run();
    const ip = request.headers.get("cf-connecting-ip") || "";
    await createAuditLog(env, {
      adminId: admin.id,
      action: "CLEAR_ALL_PRODUCTS",
      targetType: "product_posts",
      targetId: "all",
      details: { clearedCount: count },
      ip
    });
    return jsonSuccess({
      message: `All ${count} existing product creatives have been cleared successfully.`,
      clearedCount: count,
      deleted: count
    });
  } catch (err) {
    console.error("Clear all products error:", err);
    return jsonError("Failed to clear product posts", 500);
  }
}
__name(handleClearAll, "handleClearAll");

// api/admin/stats.js
async function onRequestGet7(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const usersCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
    const pendingTasks = await env.DB.prepare("SELECT COUNT(*) as count FROM task_submissions WHERE status = 'pending'").first();
    const pendingWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'pending'").first();
    const completedWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'completed'").first();
    const taskAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(approved_views), 0) as total_approved_views,
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(reward_amount_ksh), 0) as total_rewards_granted_ksh
      FROM task_submissions
      WHERE status = 'approved'
    `).first();
    const walletAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(available_balance_ksh), 0) as total_available_in_system,
        COALESCE(SUM(reserved_balance_ksh), 0) as total_reserved_in_system
      FROM wallets
    `).first();
    const pendingPayments = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM payment_transactions WHERE status = 'pending'").first();
    const productsCount = await env.DB.prepare("SELECT COUNT(*) as count FROM product_posts WHERE status = 'active'").first();
    const surveyAggregates = await env.DB.prepare(`
      SELECT 
        (SELECT COUNT(*) FROM surveys WHERE is_active = 1) as active_surveys_count,
        (SELECT COUNT(*) FROM survey_responses) as total_responses_count,
        (SELECT COALESCE(SUM(reward_amount_ksh), 0) FROM survey_responses) as total_survey_rewards_ksh
    `).first().catch(() => null);
    const bonusAggregates = await env.DB.prepare(`
      SELECT
        COALESCE(SUM(total_disbursed_ksh), 0) as total_bonus_disbursed_ksh,
        COALESCE(SUM(recipient_count), 0) as total_bonus_recipients
      FROM bonus_distributions
    `).first().catch(() => null);
    return jsonSuccess({
      metrics: {
        totalUsers: usersCount?.count || 0,
        pendingPaymentsCount: pendingPayments?.count || 0,
        pendingPaymentsAmountKsh: pendingPayments?.total_amount || 0,
        totalProductsCount: productsCount?.count || 0,
        pendingTasksCount: pendingTasks?.count || 0,
        pendingWithdrawalsCount: pendingWithdrawals?.count || 0,
        pendingWithdrawalsAmountKsh: pendingWithdrawals?.total_amount || 0,
        completedWithdrawalsCount: completedWithdrawals?.count || 0,
        totalDisbursedKsh: completedWithdrawals?.total_amount || 0,
        totalApprovedViews: taskAggregates?.total_approved_views || 0,
        totalReportedViews: taskAggregates?.total_reported_views || 0,
        totalRewardsGrantedKsh: taskAggregates?.total_rewards_granted_ksh || 0,
        activeSurveysCount: surveyAggregates?.active_surveys_count || 0,
        totalSurveyResponsesCount: surveyAggregates?.total_responses_count || 0,
        totalSurveyRewardsKsh: surveyAggregates?.total_survey_rewards_ksh || 0,
        totalBonusDisbursedKsh: bonusAggregates?.total_bonus_disbursed_ksh || 0,
        totalBonusRecipientsCount: bonusAggregates?.total_bonus_recipients || 0,
        totalAvailableInSystemKsh: walletAggregates?.total_available_in_system || 0,
        totalReservedInSystemKsh: walletAggregates?.total_reserved_in_system || 0
      }
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    return jsonError("Failed to fetch system metrics", 500);
  }
}
__name(onRequestGet7, "onRequestGet");

// api/admin/surveys.js
async function onRequestGet8(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const { results: surveys } = await env.DB.prepare(`
      SELECT s.*,
        (SELECT COUNT(*) FROM survey_responses sr WHERE sr.survey_id = s.id) as response_count,
        (SELECT COALESCE(SUM(reward_amount_ksh), 0) FROM survey_responses sr WHERE sr.survey_id = s.id) as total_payout_ksh
      FROM surveys s
      ORDER BY s.created_at DESC
    `).all();
    const statsRow = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_surveys,
        COALESCE(SUM(completions_count), 0) as total_completions,
        (SELECT COUNT(*) FROM survey_responses) as verified_responses,
        (SELECT COALESCE(SUM(reward_amount_ksh), 0) FROM survey_responses) as total_paid_ksh
      FROM surveys
    `).first().catch(() => null);
    const formattedSurveys = (surveys || []).map((s) => {
      let questions = [];
      try {
        questions = JSON.parse(s.questions);
      } catch (e) {
        questions = [];
      }
      return {
        ...s,
        questionsCount: questions.length,
        questions
      };
    });
    return jsonSuccess({
      surveys: formattedSurveys,
      stats: {
        totalSurveys: statsRow?.total_surveys || 0,
        totalCompletions: statsRow?.total_completions || 0,
        verifiedResponses: statsRow?.verified_responses || 0,
        totalPaidKsh: statsRow?.total_paid_ksh || 0
      }
    });
  } catch (err) {
    console.error("Admin fetch surveys error:", err);
    return jsonError("Failed to fetch admin surveys", 500);
  }
}
__name(onRequestGet8, "onRequestGet");
async function onRequestPost5(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { action } = body;
  const now = Math.floor(Date.now() / 1e3);
  const ip = request.headers.get("cf-connecting-ip") || "";
  try {
    if (action === "create") {
      const { title, category, description, rewardKsh, estimatedMinutes, questions, maxCompletions, targetPackageId } = body;
      if (!title || !title.trim()) {
        return jsonError("Survey title is required", 400);
      }
      if (!description || !description.trim()) {
        return jsonError("Survey description is required", 400);
      }
      const reward = parseInt(rewardKsh, 10);
      if (isNaN(reward) || reward < 10) {
        return jsonError("Reward must be at least KSh 10 per completion", 400);
      }
      const estMins = parseInt(estimatedMinutes, 10) || 3;
      const maxComp = parseInt(maxCompletions, 10) || 5e3;
      if (!Array.isArray(questions) || questions.length === 0) {
        return jsonError("Please provide at least one survey question", 400);
      }
      const cleanedQuestions = [];
      for (let i = 0; i < questions.length; i++) {
        const q = questions[i];
        if (!q.text || !q.text.trim()) {
          return jsonError(`Question #${i + 1} text is required`, 400);
        }
        if (!Array.isArray(q.options) || q.options.length < 2) {
          return jsonError(`Question #${i + 1} must have at least 2 choices / options`, 400);
        }
        cleanedQuestions.push({
          id: q.id || `q${i + 1}`,
          text: q.text.trim(),
          options: q.options.map((opt) => String(opt).trim()).filter(Boolean)
        });
      }
      const surveyId = generateId("srv");
      await env.DB.prepare(`
        INSERT INTO surveys (id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
      `).bind(
        surveyId,
        title.trim(),
        (category || "Consumer Habits").trim(),
        description.trim(),
        reward,
        estMins,
        JSON.stringify(cleanedQuestions),
        targetPackageId || null,
        maxComp,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "CREATE_SURVEY",
        targetType: "survey",
        targetId: surveyId,
        details: { title, rewardKsh: reward, questionsCount: cleanedQuestions.length },
        ip
      });
      return jsonSuccess({
        message: `Paid survey "${title}" created successfully with reward KSh ${reward}!`,
        surveyId
      }, 201);
    } else if (action === "toggle") {
      const { surveyId } = body;
      if (!surveyId) return jsonError("surveyId is required", 400);
      const existing = await env.DB.prepare("SELECT id, title, is_active FROM surveys WHERE id = ?").bind(surveyId).first();
      if (!existing) return jsonError("Survey not found", 404);
      const newStatus = existing.is_active ? 0 : 1;
      await env.DB.prepare("UPDATE surveys SET is_active = ? WHERE id = ?").bind(newStatus, surveyId).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: newStatus ? "ACTIVATE_SURVEY" : "PAUSE_SURVEY",
        targetType: "survey",
        targetId: surveyId,
        details: { title: existing.title, is_active: newStatus },
        ip
      });
      return jsonSuccess({
        message: `Survey status updated to ${newStatus ? "Active" : "Paused"}.`,
        isActive: newStatus
      });
    } else if (action === "delete") {
      const { surveyId } = body;
      if (!surveyId) return jsonError("surveyId is required", 400);
      const existing = await env.DB.prepare("SELECT id, title FROM surveys WHERE id = ?").bind(surveyId).first();
      if (!existing) return jsonError("Survey not found", 404);
      await env.DB.prepare("DELETE FROM surveys WHERE id = ?").bind(surveyId).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "DELETE_SURVEY",
        targetType: "survey",
        targetId: surveyId,
        details: { title: existing.title },
        ip
      });
      return jsonSuccess({
        message: `Survey "${existing.title}" deleted.`
      });
    } else {
      return jsonError(`Unsupported survey action: ${action}`, 400);
    }
  } catch (err) {
    console.error("Admin survey action error:", err);
    return jsonError("Failed to execute survey action", 500);
  }
}
__name(onRequestPost5, "onRequestPost");

// api/admin/tasks.js
async function onRequestGet9(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT ts.id, ts.user_id, ts.campaign_id, ts.package_id, ts.reported_views,
             ts.approved_views, ts.reward_rate_ksh, ts.reward_amount_ksh,
             ts.evidence_text, ts.evidence_id, ts.status, ts.admin_notes,
             ts.created_at, ts.reviewed_at,
             u.name as user_name, u.email as user_email, u.phone as user_phone,
             c.title as campaign_title, p.name as package_name, p.max_views_per_task
      FROM task_submissions ts
      JOIN users u ON ts.user_id = u.id
      LEFT JOIN campaigns c ON ts.campaign_id = c.id
      LEFT JOIN packages p ON ts.package_id = p.id
    `;
    let params = [];
    if (filterStatus === "pending") {
      query += ` WHERE ts.status = 'pending' ORDER BY ts.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY ts.created_at DESC LIMIT 100`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      submissions: results || []
    });
  } catch (err) {
    console.error("Admin fetch tasks error:", err);
    return jsonError("Failed to fetch submissions for review", 500);
  }
}
__name(onRequestGet9, "onRequestGet");
async function onRequestPost6(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { submissionId, action, approvedViews, notes } = body;
  if (!submissionId || !action) {
    return jsonError('submissionId and action ("approve" | "reject") are required', 400);
  }
  try {
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    const task = await env.DB.prepare(`
      SELECT ts.*, p.max_views_per_task
      FROM task_submissions ts
      LEFT JOIN packages p ON ts.package_id = p.id
      WHERE ts.id = ?
      LIMIT 1
    `).bind(submissionId).first();
    if (!task) {
      return jsonError("Task submission not found", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "approve" || action === "modify") {
      const views = parseInt(approvedViews, 10);
      if (isNaN(views) || views < 0) {
        return jsonError("Please specify valid approved views (0 or greater)", 400);
      }
      const rate = task.reward_rate_ksh || 20;
      const newRewardKsh = Math.round(views * rate);
      const previousRewardKsh = task.status === "approved" ? task.reward_amount_ksh || 0 : 0;
      const rewardDeltaKsh = newRewardKsh - previousRewardKsh;
      let wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(task.user_id).first();
      if (!wallet) {
        const walletId = generateId("wal");
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, task.user_id, now).run().catch(() => {
        });
        wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(task.user_id).first();
      }
      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curViewsBal = (wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef ? curAvail - curRef : wallet?.views_balance_ksh || 0;
      const nextViewsBal = Math.max(0, curViewsBal + rewardDeltaKsh);
      const nextAvailBal = Math.max(0, nextViewsBal + curRef);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + rewardDeltaKsh);
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'approved',
            approved_views = ?,
            reported_views = CASE WHEN ? > reported_views THEN ? ELSE reported_views END,
            reward_amount_ksh = ?,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ?
      `).bind(views, views, views, newRewardKsh, notes || "Verified screenshot evidence", admin.id, now, task.id).run();
      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextAvailBal, nextLifetime, now, task.user_id).run();
      if (rewardDeltaKsh !== 0) {
        const txId = generateId("tx");
        await env.DB.prepare(`
          INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
          VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
        `).bind(
          txId,
          wallet.id,
          task.user_id,
          rewardDeltaKsh,
          nextAvailBal,
          task.id,
          `Campaign reward credited: ${views} approved WhatsApp Status views @ KSh ${rate}/view`,
          now
        ).run();
      }
      await createAuditLog(env, {
        adminId: admin.id,
        action: task.status === "approved" ? "MODIFY_APPROVED_TASK" : "APPROVE_TASK",
        targetType: "task_submission",
        targetId: task.id,
        details: { approvedViews: views, newRewardKsh, rewardDeltaKsh, notes },
        ip
      });
      return jsonSuccess({
        message: `Task submission ${task.status === "approved" ? "updated" : "approved"}! ${views} views (KSh ${newRewardKsh.toLocaleString()}) credited to partner wallet.`,
        task: {
          id: task.id,
          status: "approved",
          approvedViews: views,
          rewardAmountKsh: newRewardKsh
        }
      });
    } else if (action === "reject") {
      if (task.status === "rejected") {
        return jsonError("This task submission is already rejected.", 409);
      }
      const reason = notes || "Screenshot evidence could not be verified or does not match requirements";
      const previousRewardKsh = task.status === "approved" ? task.reward_amount_ksh || 0 : 0;
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'rejected',
            approved_views = 0,
            reward_amount_ksh = 0,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ?
      `).bind(reason, admin.id, now, task.id).run();
      if (previousRewardKsh > 0) {
        await env.DB.prepare(`
          UPDATE wallets
          SET views_balance_ksh = MAX(0, COALESCE(views_balance_ksh, 0) - ?),
              available_balance_ksh = MAX(0, COALESCE(available_balance_ksh, 0) - ?),
              lifetime_earnings_ksh = MAX(0, COALESCE(lifetime_earnings_ksh, 0) - ?),
              updated_at = ?
          WHERE user_id = ?
        `).bind(previousRewardKsh, previousRewardKsh, previousRewardKsh, now, task.user_id).run();
      }
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_TASK",
        targetType: "task_submission",
        targetId: task.id,
        details: { reason },
        ip
      });
      return jsonSuccess({
        message: "Task submission has been rejected.",
        task: {
          id: task.id,
          status: "rejected",
          reason
        }
      });
    } else {
      return jsonError('Invalid action specified. Must be "approve" or "reject".', 400);
    }
  } catch (err) {
    console.error("Admin review error:", err);
    return jsonError("Failed to process task review. Please try again.", 500);
  }
}
__name(onRequestPost6, "onRequestPost");

// api/admin/users.js
async function onRequestGet10(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    await env.DB.prepare("ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    const url = new URL(request.url);
    const search = url.searchParams.get("q") || "";
    let query = `
      SELECT 
        u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
        COALESCE(u.submission_tickets, 0) as submission_tickets,
        COALESCE(w.available_balance_ksh, 0) as available_balance_ksh,
        COALESCE(w.views_balance_ksh, 0) as views_balance_ksh,
        COALESCE(w.referrals_balance_ksh, 0) as referrals_balance_ksh,
        COALESCE(w.surveys_balance_ksh, 0) as surveys_balance_ksh,
        COALESCE(w.reserved_balance_ksh, 0) as reserved_balance_ksh,
        COALESCE(w.lifetime_earnings_ksh, 0) as lifetime_earnings_ksh,
        COALESCE(w.lifetime_withdrawn_ksh, 0) as lifetime_withdrawn_ksh,
        (
          SELECT COALESCE(SUM(ts.reported_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id
        ) as total_reported_views,
        (
          SELECT COALESCE(SUM(ts.approved_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id AND ts.status = 'approved'
        ) as total_approved_views,
        (
          SELECT COALESCE(SUM(ts.reported_views), 0)
          FROM task_submissions ts
          WHERE ts.user_id = u.id AND ts.status = 'pending'
        ) as pending_views,
        p.id as active_package_id,
        p.name as active_package_name,
        p.slug as active_package_slug,
        p.reward_per_view_ksh as active_package_rate,
        up.activated_at as package_activated_at,
        (
          SELECT p_pen.name 
          FROM user_packages up_pen 
          JOIN packages p_pen ON up_pen.package_id = p_pen.id 
          WHERE up_pen.user_id = u.id AND up_pen.status = 'pending_verification' 
          LIMIT 1
        ) as pending_package_name
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      LEFT JOIN user_packages up ON u.id = up.user_id AND up.status = 'active'
      LEFT JOIN packages p ON up.package_id = p.id
    `;
    const params = [];
    if (search.trim()) {
      const term = `%${search.trim().toLowerCase()}%`;
      query += ` WHERE LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ? OR u.phone LIKE ?`;
      params.push(term, term, term);
    }
    query += ` ORDER BY u.created_at DESC LIMIT 150`;
    const stmt = params.length > 0 ? env.DB.prepare(query).bind(...params) : env.DB.prepare(query);
    const { results } = await stmt.all();
    return jsonSuccess({
      users: results || []
    });
  } catch (err) {
    console.error("Admin fetch users error:", err);
    return jsonError("Failed to fetch user directory", 500);
  }
}
__name(onRequestGet10, "onRequestGet");
async function onRequestPost7(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const targetUserId = body.targetUserId || body.userId;
  const { action, packageId, newStatus, newRole, userIds } = body;
  if (!action) {
    return jsonError("action is required", 400);
  }
  if (action === "bulk_delete_users") {
    const ids = Array.isArray(userIds) ? userIds.filter(Boolean) : [];
    if (ids.length === 0) {
      return jsonError("Please select at least one partner to delete", 400);
    }
    const ip = request.headers.get("cf-connecting-ip") || "";
    const deleted = [];
    const skipped = [];
    for (const uid of ids) {
      if (uid === admin.id) {
        skipped.push({ id: uid, reason: "Cannot delete active admin session" });
        continue;
      }
      const targetRow = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE id = ?").bind(uid).first();
      if (!targetRow) {
        skipped.push({ id: uid, reason: "Not found" });
        continue;
      }
      if (targetRow.role === "admin") {
        skipped.push({ id: uid, reason: "Cannot delete administrator account" });
        continue;
      }
      await deletePartnerCascade(env, uid);
      deleted.push({ id: uid, email: targetRow.email, name: targetRow.name });
    }
    await createAuditLog(env, {
      adminId: admin.id,
      action: "ADMIN_BULK_DELETE_USERS",
      targetType: "users",
      targetId: "bulk",
      details: { deletedCount: deleted.length, skippedCount: skipped.length, deletedEmails: deleted.map((d) => d.email) },
      ip
    });
    return jsonSuccess({
      message: `Deleted ${deleted.length} partner account(s)${skipped.length ? ` (${skipped.length} skipped)` : ""}.`,
      deletedCount: deleted.length,
      skipped
    });
  }
  if (!targetUserId) {
    return jsonError("targetUserId and action are required", 400);
  }
  try {
    await env.DB.prepare("ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    const target = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetUserId).first();
    if (!target) {
      return jsonError("Target user not found", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "assign_package") {
      if (!packageId) {
        return jsonError("packageId is required to assign package", 400);
      }
      const pkg = await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(packageId).first();
      if (!pkg) {
        return jsonError("Selected package was not found", 404);
      }
      await env.DB.prepare("UPDATE user_packages SET status = 'expired' WHERE user_id = ? AND status = 'active'").bind(target.id).run();
      await env.DB.prepare("DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'").bind(target.id).run();
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'active', ?)
      `).bind(userPackageId, target.id, pkg.id, now).run();
      await awardReferralCommission(env, target.id, pkg.id, pkg.name, pkg.price_ksh);
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_ASSIGN_PACKAGE",
        targetType: "user",
        targetId: target.id,
        details: { packageId: pkg.id, packageName: pkg.name, assignedTo: target.email },
        ip
      });
      return jsonSuccess({
        message: `Package ${pkg.name} manually activated for ${target.name} (${target.email})!`,
        package: pkg
      });
    } else if (action === "toggle_status") {
      const nextStatus = newStatus || (target.status === "active" ? "suspended" : "active");
      await env.DB.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").bind(nextStatus, now, target.id).run();
      if (nextStatus === "suspended") {
        await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id).run();
      }
      await createAuditLog(env, {
        adminId: admin.id,
        action: "TOGGLE_USER_STATUS",
        targetType: "user",
        targetId: target.id,
        details: { oldStatus: target.status, newStatus: nextStatus },
        ip
      });
      return jsonSuccess({
        message: `User ${target.name} status updated to ${nextStatus}.`,
        status: nextStatus
      });
    } else if (action === "toggle_role") {
      const nextRole = newRole || (target.role === "admin" ? "user" : "admin");
      if (nextRole === "admin" && target.email.toLowerCase() !== "mentorbravin@gmail.com") {
        return jsonError("Only mentorbravin@gmail.com can hold the Administrator role.", 400);
      }
      if (target.email.toLowerCase() === "mentorbravin@gmail.com" && nextRole !== "admin") {
        return jsonError("Primary administrator account cannot be demoted.", 400);
      }
      await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").bind(nextRole, now, target.id).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "TOGGLE_USER_ROLE",
        targetType: "user",
        targetId: target.id,
        details: { oldRole: target.role, newRole: nextRole },
        ip
      });
      return jsonSuccess({
        message: `User ${target.name} role updated to ${nextRole}.`,
        role: nextRole
      });
    } else if (action === "modify_views") {
      let rate = body.rate ? parseFloat(body.rate) : null;
      if (!rate || isNaN(rate) || rate <= 0) {
        const activePkg = await env.DB.prepare(`
          SELECT p.reward_per_view_ksh, p.id as package_id
          FROM user_packages up
          JOIN packages p ON up.package_id = p.id
          WHERE up.user_id = ? AND up.status = 'active'
          ORDER BY up.activated_at DESC
          LIMIT 1
        `).bind(target.id).first();
        rate = activePkg ? activePkg.reward_per_view_ksh : 20;
      }
      const curViewsRow = await env.DB.prepare(`
        SELECT COALESCE(SUM(CASE WHEN status = 'approved' THEN approved_views ELSE 0 END), 0) as approved_views
        FROM task_submissions
        WHERE user_id = ?
      `).bind(target.id).first();
      const currentApprovedViews = curViewsRow ? curViewsRow.approved_views || 0 : 0;
      const rawViewsStr = String(body.views ?? body.viewsDelta ?? "").trim();
      let views = 0;
      if (body.mode === "set" || rawViewsStr.startsWith("=")) {
        const targetTotalViews = parseInt(rawViewsStr.replace(/^=/, ""), 10);
        if (isNaN(targetTotalViews) || targetTotalViews < 0) {
          return jsonError("Please specify a valid non-negative target views count", 400);
        }
        views = targetTotalViews - currentApprovedViews;
      } else {
        views = parseInt(rawViewsStr, 10);
      }
      if (isNaN(views) || views === 0) {
        return jsonError("Please specify a valid non-zero views adjustment count (e.g. 50, -20, or =100)", 400);
      }
      const rewardKsh = Math.round(views * rate);
      const note = (body.note || body.reason || "Admin views modification").trim();
      let wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(target.id).first();
      if (!wallet) {
        const walletId = generateId("wal");
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, target.id, now).run().catch(() => {
        });
        wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(target.id).first();
      }
      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curViewsBal = (wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef ? curAvail - curRef : wallet?.views_balance_ksh || 0;
      const nextViewsBal = Math.max(0, curViewsBal + rewardKsh);
      const nextAvailBal = Math.max(0, nextViewsBal + curRef);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + rewardKsh);
      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextAvailBal, nextLifetime, now, target.id).run();
      const taskId = generateId("tsk_adm");
      if (views > 0) {
        const activePkgRow = await env.DB.prepare(`
          SELECT up.package_id FROM user_packages up JOIN packages p ON up.package_id = p.id WHERE up.user_id = ? AND up.status = 'active' ORDER BY up.activated_at DESC LIMIT 1
        `).bind(target.id).first();
        const pkgId = activePkgRow ? activePkgRow.package_id : null;
        await env.DB.prepare(`
          INSERT INTO task_submissions (
            id, user_id, campaign_id, package_id, reported_views, approved_views,
            reward_rate_ksh, reward_amount_ksh, evidence_text, evidence_id, status,
            admin_notes, reviewed_by, reviewed_at, created_at
          )
          VALUES (?, ?, NULL, ?, ?, ?, ?, ?, ?, NULL, 'approved', ?, ?, ?, ?)
        `).bind(
          taskId,
          target.id,
          pkgId,
          views,
          views,
          rate,
          rewardKsh,
          `Admin views credit: +${views} views @ KSh ${rate}/view`,
          note,
          admin.id,
          now,
          now
        ).run();
      } else {
        let remainingToDeduct = Math.abs(views);
        const { results: existingTasks } = await env.DB.prepare(`
          SELECT id, reported_views, approved_views, reward_rate_ksh, reward_amount_ksh
          FROM task_submissions
          WHERE user_id = ? AND (approved_views > 0 OR reported_views > 0)
          ORDER BY created_at DESC
        `).bind(target.id).all();
        for (const t of existingTasks || []) {
          if (remainingToDeduct <= 0) break;
          const curApp = t.approved_views || 0;
          const curRep = t.reported_views || 0;
          const deductCount = Math.min(remainingToDeduct, Math.max(curApp, curRep));
          if (deductCount > 0) {
            const newApp = Math.max(0, curApp - deductCount);
            const newRep = Math.max(0, curRep - deductCount);
            const newRew = Math.max(0, newApp * (t.reward_rate_ksh || rate));
            await env.DB.prepare(`
              UPDATE task_submissions
              SET approved_views = ?,
                  reported_views = ?,
                  reward_amount_ksh = ?,
                  admin_notes = ?,
                  reviewed_by = ?,
                  reviewed_at = ?
              WHERE id = ?
            `).bind(newApp, newRep, newRew, note, admin.id, now, t.id).run();
            remainingToDeduct -= deductCount;
          }
        }
      }
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        target.id,
        rewardKsh,
        nextAvailBal,
        taskId,
        `Admin views adjustment: ${views >= 0 ? "+" : ""}${views} views @ KSh ${rate}/view (${note})`,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_MODIFY_VIEWS",
        targetType: "user",
        targetId: target.id,
        details: { views, rate, rewardKsh, note, userEmail: target.email, availableBalanceKsh: nextAvailBal, viewsBalanceKsh: nextViewsBal },
        ip
      });
      return jsonSuccess({
        message: `Successfully adjusted ${views >= 0 ? "+" : ""}${views} views (${rewardKsh >= 0 ? "+KSh " : "-KSh "}${Math.abs(rewardKsh).toLocaleString()}) for ${target.name}! New Available Balance: KSh ${nextAvailBal.toLocaleString()}.`,
        views,
        rate,
        rewardKsh,
        availableBalanceKsh: nextAvailBal,
        viewsBalanceKsh: nextViewsBal
      });
    } else if (action === "modify_balance" || action === "adjust_balance") {
      let balanceType = "views";
      if (body.balanceType === "referrals" || body.balanceType === "referral") {
        balanceType = "referrals";
      } else if (body.balanceType === "surveys" || body.balanceType === "survey") {
        balanceType = "surveys";
      }
      const rawAmountStr = String(body.amount ?? body.amountKsh ?? "").trim();
      const note = (body.note || body.reason || "Admin wallet balance modification").trim();
      let wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(target.id).first();
      if (!wallet) {
        const walletId = generateId("wal");
        await env.DB.prepare(`
          INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, target.id, now).run().catch(() => {
        });
        wallet = await env.DB.prepare("SELECT * FROM wallets WHERE user_id = ?").bind(target.id).first();
      }
      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curSurveys = wallet?.surveys_balance_ksh || 0;
      const curViews = (wallet?.views_balance_ksh || 0) === 0 && curAvail > curRef + curSurveys ? curAvail - curRef - curSurveys : wallet?.views_balance_ksh || 0;
      let deltaKsh = 0;
      if (body.mode === "set" || rawAmountStr.startsWith("=")) {
        const targetAmount = parseInt(rawAmountStr.replace(/^=/, ""), 10);
        if (isNaN(targetAmount) || targetAmount < 0) {
          return jsonError("Please enter a valid non-negative balance amount in KSh", 400);
        }
        if (balanceType === "referrals") {
          deltaKsh = targetAmount - curRef;
        } else if (balanceType === "surveys") {
          deltaKsh = targetAmount - curSurveys;
        } else {
          deltaKsh = targetAmount - curViews;
        }
      } else {
        deltaKsh = parseInt(rawAmountStr, 10);
      }
      if (isNaN(deltaKsh) || deltaKsh === 0) {
        return jsonError("Please enter a valid non-zero balance change in KSh (e.g. 1000, -500, or =5000)", 400);
      }
      const nextViewsBal = balanceType === "views" ? Math.max(0, curViews + deltaKsh) : curViews;
      const nextRefBal = balanceType === "referrals" ? Math.max(0, curRef + deltaKsh) : curRef;
      const nextSurveysBal = balanceType === "surveys" ? Math.max(0, curSurveys + deltaKsh) : curSurveys;
      const nextAvailBal = Math.max(0, nextViewsBal + nextRefBal + nextSurveysBal);
      const nextLifetime = Math.max(0, (wallet?.lifetime_earnings_ksh || 0) + deltaKsh);
      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            referrals_balance_ksh = ?,
            surveys_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViewsBal, nextRefBal, nextSurveysBal, nextAvailBal, nextLifetime, now, target.id).run();
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        target.id,
        deltaKsh,
        nextAvailBal,
        admin.id,
        `Admin ${balanceType === "referrals" ? "Referral" : "Status Views"} balance adjustment: ${deltaKsh >= 0 ? "+KSh " : "-KSh "}${Math.abs(deltaKsh).toLocaleString()} (${note})`,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_MODIFY_BALANCE",
        targetType: "user",
        targetId: target.id,
        details: { balanceType, deltaKsh, viewsBalanceKsh: nextViewsBal, referralsBalanceKsh: nextRefBal, availableBalanceKsh: nextAvailBal, note, userEmail: target.email },
        ip
      });
      return jsonSuccess({
        message: `Updated ${target.name}'s ${balanceType === "referrals" ? "Referral" : "Status Views"} balance by ${deltaKsh >= 0 ? "+KSh " : "-KSh "}${Math.abs(deltaKsh).toLocaleString()}! Total Available Balance: KSh ${nextAvailBal.toLocaleString()}.`,
        balanceType,
        deltaKsh,
        viewsBalanceKsh: nextViewsBal,
        referralsBalanceKsh: nextRefBal,
        availableBalanceKsh: nextAvailBal
      });
    } else if (action === "grant_submission_ticket") {
      const tickets = parseInt(body.tickets || body.count || 1, 10);
      if (isNaN(tickets) || tickets <= 0) {
        return jsonError("Please enter a valid positive number of submission tickets to grant", 400);
      }
      const note = (body.note || body.reason || "18-hour rule waiver ticket").trim();
      await env.DB.prepare(`
        UPDATE users
        SET submission_tickets = COALESCE(submission_tickets, 0) + ?,
            updated_at = ?
        WHERE id = ?
      `).bind(tickets, now, target.id).run();
      const updatedUser = await env.DB.prepare("SELECT submission_tickets FROM users WHERE id = ?").bind(target.id).first();
      const totalTickets = updatedUser ? updatedUser.submission_tickets : tickets;
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_GRANT_SUBMISSION_TICKET",
        targetType: "user",
        targetId: target.id,
        details: { ticketsGranted: tickets, totalTickets, note, userEmail: target.email },
        ip
      });
      return jsonSuccess({
        message: `Granted ${tickets} submission ticket(s) to ${target.name}. Total tickets: ${totalTickets}. The user can now bypass the 18-hour cooldown rule!`,
        ticketsGranted: tickets,
        totalTickets
      });
    } else if (action === "delete_user") {
      if (target.id === admin.id) {
        return jsonError("You cannot delete your own active administrator account", 400);
      }
      if (target.role === "admin") {
        return jsonError("Administrator accounts cannot be deleted here", 403);
      }
      await deletePartnerCascade(env, target.id);
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_DELETE_USER",
        targetType: "user",
        targetId: target.id,
        details: { name: target.name, email: target.email, phone: target.phone },
        ip
      });
      return jsonSuccess({
        message: `Partner "${target.name}" (${target.email}) and all associated records have been deleted permanently.`,
        deletedUserId: target.id
      });
    } else {
      return jsonError("Invalid action specified", 400);
    }
  } catch (err) {
    console.error("Admin user action error:", err);
    return jsonError("Failed to perform user administrative action", 500);
  }
}
__name(onRequestPost7, "onRequestPost");
async function onRequestDelete3(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  const url = new URL(request.url);
  let targetId = url.searchParams.get("id") || url.searchParams.get("userId");
  let userIds = null;
  if (!targetId) {
    try {
      const text = await request.text();
      if (text && text.trim()) {
        const body = JSON.parse(text);
        targetId = body?.userId || body?.targetUserId || body?.id;
        if (Array.isArray(body?.userIds)) userIds = body.userIds;
      }
    } catch (e) {
    }
  }
  const ip = request.headers.get("cf-connecting-ip") || "";
  try {
    if (Array.isArray(userIds) && userIds.length > 0) {
      let deletedCount = 0;
      for (const uid of userIds) {
        if (!uid || uid === admin.id) continue;
        const target2 = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(uid).first();
        if (target2 && target2.role !== "admin") {
          await deletePartnerCascade(env, uid);
          deletedCount++;
        }
      }
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_BULK_DELETE_USERS",
        targetType: "users",
        targetId: "bulk",
        details: { deletedCount },
        ip
      });
      return jsonSuccess({ message: `Deleted ${deletedCount} partner account(s).`, deletedCount });
    }
    if (!targetId) {
      return jsonError("Partner userId is required", 400);
    }
    if (targetId === admin.id) {
      return jsonError("Cannot delete active administrator account", 400);
    }
    const target = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE id = ?").bind(targetId).first();
    if (!target) {
      return jsonError("Partner account not found", 404);
    }
    if (target.role === "admin") {
      return jsonError("Cannot delete administrator account", 403);
    }
    await deletePartnerCascade(env, targetId);
    await createAuditLog(env, {
      adminId: admin.id,
      action: "ADMIN_DELETE_USER",
      targetType: "user",
      targetId: target.id,
      details: { name: target.name, email: target.email },
      ip
    });
    return jsonSuccess({
      message: `Partner "${target.name}" has been deleted.`,
      deletedUserId: target.id
    });
  } catch (err) {
    console.error("Delete partner error:", err);
    return jsonError("Failed to delete partner account", 500);
  }
}
__name(onRequestDelete3, "onRequestDelete");
async function deletePartnerCascade(env, userId) {
  await env.DB.prepare("DELETE FROM bonus_recipient_logs WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM survey_responses WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM referrals WHERE referrer_id = ? OR referred_user_id = ?").bind(userId, userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM wallet_transactions WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM withdrawal_requests WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM payment_transactions WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("UPDATE task_submissions SET reviewed_by = NULL WHERE reviewed_by = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("UPDATE withdrawal_requests SET processed_by = NULL WHERE processed_by = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM task_submissions WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM user_packages WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM wallets WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM admin_audit_logs WHERE admin_id = ?").bind(userId).run().catch(() => {
  });
  await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
}
__name(deletePartnerCascade, "deletePartnerCascade");

// api/admin/withdrawals.js
async function onRequestGet11(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT wr.id, wr.user_id, wr.wallet_id, wr.amount_ksh, wr.phone_number,
             wr.status, wr.balance_type, wr.mpesa_receipt_number, wr.rejection_reason,
             wr.created_at, wr.processed_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone
      FROM withdrawal_requests wr
      JOIN users u ON wr.user_id = u.id
    `;
    if (filterStatus === "pending") {
      query += ` WHERE wr.status = 'pending' ORDER BY wr.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY wr.created_at DESC LIMIT 100`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      withdrawals: results || []
    });
  } catch (err) {
    console.error("Admin fetch withdrawals error:", err);
    return jsonError("Failed to fetch withdrawal queue", 500);
  }
}
__name(onRequestGet11, "onRequestGet");
async function onRequestPost8(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { withdrawalId, action, mpesaReceipt, reason } = body;
  if (!withdrawalId || !action) {
    return jsonError('withdrawalId and action ("complete" | "reject") are required', 400);
  }
  try {
    const withdrawal = await env.DB.prepare(`
      SELECT wr.*, w.available_balance_ksh, w.reserved_balance_ksh
      FROM withdrawal_requests wr
      JOIN wallets w ON wr.wallet_id = w.id
      WHERE wr.id = ?
      LIMIT 1
    `).bind(withdrawalId).first();
    if (!withdrawal) {
      return jsonError("Withdrawal request not found", 404);
    }
    if (withdrawal.status !== "pending") {
      return jsonError(`This withdrawal request is already marked as ${withdrawal.status}`, 409);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "complete") {
      if (!mpesaReceipt || mpesaReceipt.trim().length < 6) {
        return jsonError("Please enter the verified M-Pesa transaction reference code (e.g. QWE45RT67Y) to confirm payout disbursement", 400);
      }
      const cleanReceipt = mpesaReceipt.trim().toUpperCase();
      const existingReceipt = await env.DB.prepare(`
        SELECT id FROM withdrawal_requests WHERE mpesa_receipt_number = ? AND id != ? LIMIT 1
      `).bind(cleanReceipt, withdrawal.id).first();
      if (existingReceipt) {
        return jsonError("This M-Pesa receipt code has already been registered for another withdrawal", 409);
      }
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'completed',
            mpesa_receipt_number = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(cleanReceipt, admin.id, now, withdrawal.id).run();
      await env.DB.prepare(`
        UPDATE wallets
        SET reserved_balance_ksh = reserved_balance_ksh - ?,
            lifetime_withdrawn_ksh = lifetime_withdrawn_ksh + ?,
            updated_at = ?
        WHERE id = ? AND reserved_balance_ksh >= ?
      `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'withdrawal_complete', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        withdrawal.wallet_id,
        withdrawal.user_id,
        withdrawal.amount_ksh,
        withdrawal.available_balance_ksh,
        withdrawal.id,
        `M-Pesa payout completed to ${withdrawal.phone_number} (M-Pesa Ref: ${cleanReceipt})`,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "COMPLETE_WITHDRAWAL",
        targetType: "withdrawal_request",
        targetId: withdrawal.id,
        details: { amountKsh: withdrawal.amount_ksh, phone: withdrawal.phone_number, mpesaReceipt: cleanReceipt },
        ip
      });
      return jsonSuccess({
        message: `Withdrawal payout marked completed with M-Pesa Ref ${cleanReceipt}.`,
        withdrawal: {
          id: withdrawal.id,
          status: "completed",
          mpesaReceipt: cleanReceipt
        }
      });
    } else if (action === "reject") {
      const rejectReason = reason || "Withdrawal could not be processed. Funds refunded to wallet.";
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'rejected',
            rejection_reason = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, admin.id, now, withdrawal.id).run();
      const newAvailable = withdrawal.available_balance_ksh + withdrawal.amount_ksh;
      if (withdrawal.balance_type === "referrals") {
        await env.DB.prepare(`
          UPDATE wallets
          SET reserved_balance_ksh = reserved_balance_ksh - ?,
              referrals_balance_ksh = referrals_balance_ksh + ?,
              available_balance_ksh = available_balance_ksh + ?,
              updated_at = ?
          WHERE id = ? AND reserved_balance_ksh >= ?
        `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      } else if (withdrawal.balance_type === "surveys") {
        await env.DB.prepare(`
          UPDATE wallets
          SET reserved_balance_ksh = reserved_balance_ksh - ?,
              surveys_balance_ksh = surveys_balance_ksh + ?,
              available_balance_ksh = available_balance_ksh + ?,
              updated_at = ?
          WHERE id = ? AND reserved_balance_ksh >= ?
        `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      } else {
        await env.DB.prepare(`
          UPDATE wallets
          SET reserved_balance_ksh = reserved_balance_ksh - ?,
              views_balance_ksh = views_balance_ksh + ?,
              available_balance_ksh = available_balance_ksh + ?,
              updated_at = ?
          WHERE id = ? AND reserved_balance_ksh >= ?
        `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      }
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'withdrawal_refund', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        withdrawal.wallet_id,
        withdrawal.user_id,
        withdrawal.amount_ksh,
        newAvailable,
        withdrawal.id,
        `Refunded reserved funds for cancelled payout: ${rejectReason}`,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_WITHDRAWAL",
        targetType: "withdrawal_request",
        targetId: withdrawal.id,
        details: { reason: rejectReason, amountKsh: withdrawal.amount_ksh },
        ip
      });
      return jsonSuccess({
        message: "Withdrawal rejected and funds refunded safely to partner wallet.",
        withdrawal: {
          id: withdrawal.id,
          status: "rejected",
          refundedAmountKsh: withdrawal.amount_ksh
        }
      });
    } else {
      return jsonError('Invalid action. Must be "complete" or "reject".', 400);
    }
  } catch (err) {
    console.error("Process withdrawal error:", err);
    return jsonError("Failed to process withdrawal request. Please try again.", 500);
  }
}
__name(onRequestPost8, "onRequestPost");

// api/auth/login.js
async function onRequestPost9(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { email, password } = body;
  const recaptchaToken = body.recaptchaToken || body["g-recaptcha-response"] || "";
  if (!email || !password) {
    return jsonError("Email and password are required", 400);
  }
  const cleanEmail = email.trim().toLowerCase();
  const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "default_ip";
  const ipCheck = await checkRateLimit(env, `login:ip:${ip}`);
  if (!ipCheck.allowed) {
    const waitMins = ipCheck.waitMinutes || 5;
    return jsonError(`Too many login attempts from this network (3 trials reached). Please wait ${waitMins} minute(s) before trying again.`, 429, {
      attempts: 3,
      remaining: 0,
      locked: true,
      waitMinutes: waitMins,
      waitSeconds: ipCheck.waitSeconds || waitMins * 60
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
      waitSeconds: emailCheck.waitSeconds || waitMins * 60
    });
  }
  const captcha = await verifyRecaptchaToken(recaptchaToken, ip, env);
  if (!captcha.ok) {
    return jsonError(captcha.error, captcha.status || 400, {
      recaptchaRequired: true,
      codes: captcha.codes
    });
  }
  try {
    let user = await env.DB.prepare(`
      SELECT id, name, email, phone, password_hash, salt, role, status, referral_code, referred_by
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(cleanEmail).first();
    if (cleanEmail === "mentorbravin@gmail.com" && (password === "@mentor123" || password === "Mentor@2026")) {
      const adminSalt = "b7e2c9d1a4f50827364b5c6d7e8f9102";
      const adminHash = password === "@mentor123" ? "cff8eb4c84f09df856787f33a136c771810d2ac6376440107e13c6e766613ac9" : "a1194e448c3ef0848f7884c1b3475daa750717a16d591efb0121cf442b5bee7e";
      const now2 = Math.floor(Date.now() / 1e3);
      if (!user) {
        const adminId = "usr_admin_mentorbravin";
        await env.DB.prepare(`
          INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
          VALUES (?, 'Bravin Mentor (Admin)', 'mentorbravin@gmail.com', '0700000000', ?, ?, 'admin', 'active', ?, ?)
        `).bind(adminId, adminHash, adminSalt, now2, now2).run();
        await env.DB.prepare(`
          INSERT OR IGNORE INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES ('wal_admin_mentorbravin', ?, 0, 0, 0, 0, ?)
        `).bind(adminId, now2).run();
        user = {
          id: adminId,
          name: "Bravin Mentor (Admin)",
          email: "mentorbravin@gmail.com",
          phone: "0700000000",
          password_hash: adminHash,
          salt: adminSalt,
          role: "admin",
          status: "active"
        };
      } else if (user.role !== "admin" || user.password_hash !== adminHash) {
        await env.DB.prepare(`
          UPDATE users SET role = 'admin', password_hash = ?, salt = ?, status = 'active', updated_at = ? WHERE id = ?
        `).bind(adminHash, adminSalt, now2, user.id).run();
        user.role = "admin";
        user.status = "active";
        user.password_hash = adminHash;
        user.salt = adminSalt;
      }
    }
    if (user && user.role === "admin" && user.email.toLowerCase() !== "mentorbravin@gmail.com") {
      user.role = "user";
      await env.DB.prepare("UPDATE users SET role = 'user' WHERE id = ?").bind(user.id).run().catch(() => {
      });
    }
    if (!user) {
      await verifyPassword(password, "00".repeat(32), "00".repeat(16));
      const failRecord = await recordFailedAttempt(env, `login:email:${cleanEmail}`, 300);
      await recordFailedAttempt(env, `login:ip:${ip}`, 300);
      if (failRecord.locked) {
        return jsonError("Too many failed sign-in attempts (3 of 3 trials used). Access is locked for 5 minutes for security.", 429, {
          attempts: 3,
          remaining: 0,
          locked: true,
          waitMinutes: 5,
          waitSeconds: 300
        });
      }
      return jsonError(`Invalid email or password. Trial ${failRecord.attempts} of 3 used (${failRecord.remaining} attempt${failRecord.remaining === 1 ? "" : "s"} remaining).`, 401, {
        attempts: failRecord.attempts,
        remaining: failRecord.remaining,
        locked: false
      });
    }
    if (user.status !== "active") {
      return jsonError("Your account has been suspended. Please contact support.", 403);
    }
    const isValid = await verifyPassword(password, user.password_hash, user.salt);
    if (!isValid) {
      const failRecord = await recordFailedAttempt(env, `login:email:${cleanEmail}`, 300);
      await recordFailedAttempt(env, `login:ip:${ip}`, 300);
      if (failRecord.locked) {
        return jsonError("Too many failed sign-in attempts (3 of 3 trials used). Access is locked for 5 minutes for security.", 429, {
          attempts: 3,
          remaining: 0,
          locked: true,
          waitMinutes: 5,
          waitSeconds: 300
        });
      }
      return jsonError(`Invalid email or password. Trial ${failRecord.attempts} of 3 used (${failRecord.remaining} attempt${failRecord.remaining === 1 ? "" : "s"} remaining).`, 401, {
        attempts: failRecord.attempts,
        remaining: failRecord.remaining,
        locked: false
      });
    }
    await clearRateLimit(env, `login:email:${cleanEmail}`);
    await clearRateLimit(env, `login:ip:${ip}`);
    const sessionToken = generateToken(32);
    const now = Math.floor(Date.now() / 1e3);
    const expiresAt = now + 7 * 86400;
    const userAgent = request.headers.get("user-agent") || "";
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
    const isHttps = request.url.startsWith("https://");
    const cookieHeader = `almai_session=${sessionToken}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800${isHttps ? "; Secure" : ""}`;
    let refCode = user.referral_code;
    if (!refCode) {
      refCode = "ALM" + user.id.replace(/[^a-zA-Z0-9]/g, "").substring(0, 6).toUpperCase();
      await env.DB.prepare("UPDATE users SET referral_code = ? WHERE id = ?").bind(refCode, user.id).run().catch(() => {
      });
    }
    return jsonSuccess({
      message: "Sign in successful. Welcome back!",
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
      "Set-Cookie": cookieHeader
    });
  } catch (err) {
    console.error("Login error:", err);
    return jsonError("Sign in failed due to a server error. Please try again.", 500);
  }
}
__name(onRequestPost9, "onRequestPost");

// api/auth/logout.js
async function onRequestPost10(context) {
  const { request, env } = context;
  const token = getSessionToken(request);
  if (token && env.DB) {
    try {
      await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
    } catch (err) {
      console.error("Logout session delete error:", err);
    }
  }
  const isHttps = request.url.startsWith("https://");
  const clearCookieHeader = `almai_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isHttps ? "; Secure" : ""}`;
  return jsonSuccess({
    message: "Signed out successfully"
  }, 200, {
    "Set-Cookie": clearCookieHeader
  });
}
__name(onRequestPost10, "onRequestPost");

// api/auth/me.js
async function onRequestGet12(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    let wallet = null;
    try {
      wallet = await env.DB.prepare(`
        SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      try {
        const legacyWallet = await env.DB.prepare(`
          SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
          FROM wallets
          WHERE user_id = ?
          LIMIT 1
        `).bind(user.id).first();
        if (legacyWallet) {
          wallet = {
            ...legacyWallet,
            surveys_balance_ksh: 0
          };
        }
      } catch (e2) {
      }
    }
    if (!wallet) {
      wallet = {
        available_balance_ksh: 0,
        views_balance_ksh: 0,
        referrals_balance_ksh: 0,
        surveys_balance_ksh: 0,
        reserved_balance_ksh: 0,
        lifetime_earnings_ksh: 0,
        lifetime_withdrawn_ksh: 0
      };
    } else {
      const refBal = Number(wallet.referrals_balance_ksh || 0);
      const surveysBal = Number(wallet.surveys_balance_ksh || 0);
      let viewsBal = Number(wallet.views_balance_ksh || 0);
      let availBal = Number(wallet.available_balance_ksh || 0);
      if (viewsBal === 0 && refBal === 0 && surveysBal === 0 && availBal > 0) {
        viewsBal = availBal;
      } else if (availBal !== viewsBal + refBal + surveysBal) {
        availBal = viewsBal + refBal + surveysBal;
      }
      wallet.views_balance_ksh = viewsBal;
      wallet.referrals_balance_ksh = refBal;
      wallet.surveys_balance_ksh = surveysBal;
      wallet.available_balance_ksh = availBal;
    }
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    const {
      activePackage,
      pendingPackage,
      expiredTrialPackage,
      isTrialActive,
      trialExpiresAt,
      trialSecondsRemaining,
      hasUsedFreeTrial,
      isTrialExpiredLockout
    } = pkgState;
    const userRow = await env.DB.prepare("SELECT COALESCE(submission_tickets, 0) as submission_tickets FROM users WHERE id = ?").bind(user.id).first().catch(() => null);
    const submissionTickets = userRow ? userRow.submission_tickets || 0 : 0;
    const latestTask = await env.DB.prepare(`
      SELECT created_at, status
      FROM task_submissions
      WHERE user_id = ? AND evidence_id IS NOT NULL
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const now = Math.floor(Date.now() / 1e3);
    let canSubmitTask = true;
    let nextSubmissionAllowedAt = now;
    let secondsRemaining = 0;
    let waivedByTicket = false;
    if (latestTask) {
      const cooldownPeriod = 18 * 60 * 60;
      const nextTime = latestTask.created_at + cooldownPeriod;
      if (now < nextTime) {
        secondsRemaining = nextTime - now;
        nextSubmissionAllowedAt = nextTime;
        if (submissionTickets > 0) {
          canSubmitTask = true;
          waivedByTicket = true;
        } else {
          canSubmitTask = false;
        }
      }
    }
    const taskStats = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(CASE WHEN status = 'pending' THEN reported_views ELSE 0 END), 0) as pending_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN approved_views ELSE 0 END), 0) as approved_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN reward_amount_ksh ELSE 0 END), 0) as total_approved_rewards_ksh,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks_count
      FROM task_submissions
      WHERE user_id = ?
    `).bind(user.id).first();
    const surveyStats = await env.DB.prepare(`
      SELECT COUNT(*) as completed_count, COALESCE(SUM(reward_amount_ksh), 0) as total_earned_ksh
      FROM survey_responses
      WHERE user_id = ?
    `).bind(user.id).first().catch(() => null);
    let recentBonuses = [];
    try {
      const { results: bonusRows } = await env.DB.prepare(`
        SELECT br.id, br.amount_ksh, br.balance_type, br.created_at, bd.campaign_title
        FROM bonus_recipient_logs br
        JOIN bonus_distributions bd ON br.distribution_id = bd.id
        WHERE br.user_id = ?
        ORDER BY br.created_at DESC
        LIMIT 3
      `).bind(user.id).all();
      recentBonuses = bonusRows || [];
    } catch (_) {
      recentBonuses = [];
    }
    return jsonSuccess({
      authenticated: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role,
        referralCode: user.referralCode,
        submissionTickets
      },
      wallet,
      activePackage: activePackage || null,
      pendingPackage: pendingPackage || null,
      expiredTrialPackage: expiredTrialPackage || null,
      hasActivePackage: Boolean(activePackage),
      isTrialActive,
      trialExpiresAt,
      trialSecondsRemaining,
      hasUsedFreeTrial,
      isTrialExpiredLockout,
      recentBonuses,
      cooldown: {
        canSubmitTask,
        nextSubmissionAllowedAt,
        secondsRemaining,
        lastSubmittedAt: latestTask ? latestTask.created_at : null,
        waivedByTicket,
        submissionTickets
      },
      stats: {
        reportedViews: taskStats?.total_reported_views || 0,
        pendingViews: taskStats?.pending_views || 0,
        approvedViews: taskStats?.approved_views || 0,
        approvedRewardsKsh: taskStats?.total_approved_rewards_ksh || 0,
        pendingTasksCount: taskStats?.pending_tasks_count || 0,
        availableBalanceKsh: wallet.available_balance_ksh,
        viewsBalanceKsh: wallet.views_balance_ksh || 0,
        referralsBalanceKsh: wallet.referrals_balance_ksh || 0,
        surveysBalanceKsh: wallet.surveys_balance_ksh || 0,
        completedSurveysCount: surveyStats?.completed_count || 0,
        totalSurveyEarningsKsh: surveyStats?.total_earned_ksh || 0,
        reservedBalanceKsh: wallet.reserved_balance_ksh,
        completedWithdrawalsKsh: wallet.lifetime_withdrawn_ksh
      }
    });
  } catch (err) {
    console.error("/api/auth/me error:", err);
    return jsonError("Failed to retrieve user profile", 500);
  }
}
__name(onRequestGet12, "onRequestGet");

// api/auth/register.js
async function onRequestPost11(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "default_ip";
  const regCheck = await checkRateLimit(env, `reg:ip:${ip}`);
  if (!regCheck.allowed) {
    return jsonError(`Too many registration attempts (3 attempts reached). For security, please wait ${regCheck.waitMinutes || 10} minute(s) before trying again.`, 429);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { name, email, phone, password, referralCode } = body;
  const recaptchaToken = body.recaptchaToken || body["g-recaptcha-response"] || "";
  if (!name || typeof name !== "string" || name.trim().length < 2) {
    return jsonError("Valid full name is required (min 2 characters)", 400);
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError("Please provide a valid email address", 400);
  }
  if (!phone || typeof phone !== "string" || phone.trim().length < 9) {
    return jsonError("Please provide a valid M-Pesa phone number (e.g. 0712345678 or 254712345678)", 400);
  }
  if (!password || typeof password !== "string" || password.length < 8) {
    return jsonError("Password must be at least 8 characters long", 400);
  }
  const captcha = await verifyRecaptchaToken(recaptchaToken, ip, env);
  if (!captcha.ok) {
    return jsonError(captcha.error, captcha.status || 400, {
      recaptchaRequired: true,
      codes: captcha.codes
    });
  }
  const cleanEmail = email.trim().toLowerCase();
  const cleanPhone = phone.trim().replace(/\s+/g, "");
  const cleanName = name.trim();
  const cleanReferral = (referralCode || "").trim();
  try {
    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? LIMIT 1"
    ).bind(cleanEmail).first();
    if (existing) {
      await recordFailedAttempt(env, `reg:ip:${ip}`, 600);
      return jsonError("An account with this email address already exists. Please log in.", 409);
    }
    await recordFailedAttempt(env, `reg:ip:${ip}`, 600);
    let referrer = null;
    if (cleanReferral) {
      referrer = await env.DB.prepare(`
        SELECT id, name, email FROM users
        WHERE (id = ? OR referral_code = ? OR referral_code = ?) AND status = 'active'
        LIMIT 1
      `).bind(cleanReferral, cleanReferral, cleanReferral.toUpperCase()).first();
    }
    const { hash, salt } = await hashPassword(password);
    const userId = generateId("usr");
    const walletId = generateId("wal");
    const now = Math.floor(Date.now() / 1e3);
    const myReferralCode = "ALM" + generateToken(3).toUpperCase();
    const referredById = referrer ? referrer.id : null;
    const initialRole = "user";
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
    if (referrer) {
      const refTrackingId = generateId("ref");
      await env.DB.prepare(`
        INSERT INTO referrals (id, referrer_id, referred_user_id, referral_code, status, created_at)
        VALUES (?, ?, ?, ?, 'registered', ?)
      `).bind(refTrackingId, referrer.id, userId, cleanReferral, now).run();
    }
    await env.DB.prepare(`
      INSERT INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
      VALUES (?, ?, 0, 0, 0, 0, ?)
    `).bind(walletId, userId, now).run();
    return jsonSuccess({
      message: referrer ? `Registration successful! You were invited by ${referrer.name}. Please sign in to activate your partner package.` : "Registration successful! Please log in with your email and password to choose and activate your partner package.",
      registered: true,
      email: cleanEmail,
      referralCode: myReferralCode,
      referredBy: referrer ? referrer.name : null
    }, 201);
  } catch (err) {
    console.error("Registration error:", err);
    return jsonError("Registration failed due to a server error. Please try again.", 500);
  }
}
__name(onRequestPost11, "onRequestPost");

// api/evidence/[id].js
async function onRequestGet13(context) {
  const { request, env, params } = context;
  const evidenceId = params.id;
  if (!evidenceId) {
    return jsonError("Evidence ID is required", 400);
  }
  const user = await authenticate(request, env);
  if (!user) {
    return jsonError("Authentication required to view evidence", 401);
  }
  try {
    const submission = await env.DB.prepare(`
      SELECT ts.user_id, te.file_name, te.file_type, te.data_base64
      FROM task_evidence te
      JOIN task_submissions ts ON ts.evidence_id = te.id
      WHERE te.id = ?
      LIMIT 1
    `).bind(evidenceId).first();
    if (!submission) {
      return jsonError("Evidence not found", 404);
    }
    if (submission.user_id !== user.id && user.role !== "admin") {
      return jsonError("Unauthorized access to this evidence file", 403);
    }
    let dataUri = submission.data_base64;
    if (!dataUri.startsWith("data:")) {
      dataUri = `data:${submission.file_type || "image/png"};base64,${dataUri}`;
    }
    const parts = dataUri.split(",");
    const mimeMatch = parts[0].match(/:(.*?);/);
    const mimeType = mimeMatch ? mimeMatch[1] : "image/png";
    const binaryStr = atob(parts[1]);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return new Response(bytes, {
      status: 200,
      headers: {
        "Content-Type": mimeType,
        "Cache-Control": "private, max-age=86400",
        "X-Content-Type-Options": "nosniff"
      }
    });
  } catch (err) {
    console.error("Evidence retrieval error:", err);
    return jsonError("Failed to fetch evidence image", 500);
  }
}
__name(onRequestGet13, "onRequestGet");

// api/inquiries.js
async function onRequestPost12(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { name, email, phone, businessName, serviceType, budgetRange, message } = body;
  if (!name || name.trim().length < 2) {
    return jsonError("Please provide your name or company representative name", 400);
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError("Please provide a valid contact email address", 400);
  }
  if (!phone || phone.trim().length < 8) {
    return jsonError("Please provide a valid phone number for our media team to reach you", 400);
  }
  if (!message || message.trim().length < 10) {
    return jsonError("Please include a brief message detailing your advertising goals (min 10 characters)", 400);
  }
  try {
    const authUser = await authenticate(request, env);
    const inquiryId = generateId("inq");
    const now = Math.floor(Date.now() / 1e3);
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
      businessName ? businessName.trim() : "Private Individual",
      serviceType || "WhatsApp Status Network Blast",
      budgetRange || "Flexible",
      message.trim(),
      now
    ).run();
    return jsonSuccess({
      message: "Thank you! Your advertising inquiry has been submitted. Our commercial media strategist will contact you within 24 hours.",
      inquiryId
    }, 201);
  } catch (err) {
    console.error("Inquiry error:", err);
    return jsonError("Failed to record inquiry. Please try again.", 500);
  }
}
__name(onRequestPost12, "onRequestPost");
async function onRequestGet14(context) {
  const { request, env } = context;
  const authUser = await authenticate(request, env);
  if (!authUser || authUser.role !== "admin" || authUser.email.toLowerCase() !== "mentorbravin@gmail.com") {
    return jsonError("Administrator access required", 403);
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
    console.error("Fetch inquiries error:", err);
    return jsonError("Failed to fetch inquiries", 500);
  }
}
__name(onRequestGet14, "onRequestGet");

// api/packages.js
async function onRequestGet15(context) {
  const { env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  try {
    await ensureFreeTrialSchema(env.DB);
    const { results } = await env.DB.prepare(`
      SELECT id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, min_withdrawal_views_ksh,
             features, badge, is_active,
             COALESCE(duration_hours, NULL) as duration_hours,
             COALESCE(is_free_trial, 0) as is_free_trial
      FROM packages
      WHERE is_active = 1
      ORDER BY price_ksh ASC
    `).all();
    const packages = (results || []).map((pkg) => ({
      ...pkg,
      features: typeof pkg.features === "string" ? JSON.parse(pkg.features) : pkg.features
    }));
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_PASSKEY && env.MPESA_SHORTCODE
    );
    return jsonSuccess({
      packages,
      paymentSettings: {
        isMpesaAutomated: isMpesaConfigured,
        paymentMode: isMpesaConfigured ? "automated_stk" : "manual_till",
        tillNumber: env.MPESA_TILL_NUMBER || "1870141",
        businessName: env.MPESA_BUSINESS_NAME || "ALMAIZA AGENCIES",
        method: "Buy Goods and Services",
        paybillOrTill: `Buy Goods Till: ${env.MPESA_TILL_NUMBER || "1870141"} (${env.MPESA_BUSINESS_NAME || "ALMAIZA AGENCIES"})`,
        paybill: env.MPESA_PAYBILL_NUMBER || env.MPESA_TILL_NUMBER || "1870141",
        accountNumber: env.MPESA_ACCOUNT_NUMBER || ""
      }
    }, 200, {
      "Cache-Control": "public, max-age=60, s-maxage=300, stale-while-revalidate=600"
    });
  } catch (err) {
    console.error("Fetch packages error:", err);
    return jsonError("Failed to fetch advertising packages", 500);
  }
}
__name(onRequestGet15, "onRequestGet");
async function onRequestPost13(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { packageId, phoneNumber, paymentReference } = body;
  if (!packageId) {
    return jsonError("packageId is required", 400);
  }
  try {
    await ensureFreeTrialSchema(env.DB);
    const pkg = await env.DB.prepare(`
      SELECT id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, min_withdrawal_views_ksh, is_active,
             COALESCE(duration_hours, NULL) as duration_hours,
             COALESCE(is_free_trial, 0) as is_free_trial
      FROM packages
      WHERE id = ? AND is_active = 1
      LIMIT 1
    `).bind(packageId).first();
    if (!pkg) {
      return jsonError("Selected package was not found or is currently inactive", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    if (pkg.price_ksh === 0 || pkg.is_free_trial === 1) {
      const pkgState = await syncAndGetUserPackageState(env.DB, user.id, now);
      if (pkgState.activePackage && pkgState.activePackage.is_free_trial === 0 && pkgState.activePackage.price_ksh > 0) {
        return jsonError("You already have an active paid partner package. The Free Trial is intended for new accounts.", 409);
      }
      if (pkgState.hasUsedFreeTrial) {
        return jsonError(
          "You have already used your 1-Day Free Trial on this account. Please upgrade to a paid partner package (Starter Pro, Exclusive, or Premium) to continue using company services.",
          409,
          { trialExpired: pkgState.isTrialExpiredLockout }
        );
      }
      const durationHours = pkg.duration_hours && pkg.duration_hours > 0 ? parseInt(pkg.duration_hours, 10) : 24;
      const expiresAt = now + durationHours * 3600;
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at, expires_at)
        VALUES (?, ?, ?, 'active', ?, ?)
      `).bind(userPackageId, user.id, pkg.id, now, expiresAt).run();
      return jsonSuccess({
        message: `${pkg.name} activated immediately! Enjoy full partner access for ${durationHours} hours (1 day). Upgrade anytime to keep your account active permanently.`,
        activated: true,
        isTrial: true,
        durationHours,
        expiresAt,
        package: pkg,
        status: "active"
      });
    }
    const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, "") : user.phone;
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_PASSKEY && env.MPESA_SHORTCODE
    );
    if (isMpesaConfigured) {
      const paymentTxId = generateId("pmt");
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_stk', 'pending', 'STK Push Triggered', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, now).run();
      return jsonSuccess({
        message: `M-Pesa STK Push initiated for KSh ${pkg.price_ksh}. Please enter your PIN on your phone.`,
        transactionId: paymentTxId,
        status: "pending_pin"
      });
    } else {
      if (!paymentReference || paymentReference.trim().length < 5) {
        return jsonError("Please enter your valid M-Pesa transaction reference (e.g. SLK89J21X) after sending payment.", 400);
      }
      const cleanRef = paymentReference.trim().toUpperCase();
      const duplicate = await env.DB.prepare(`
        SELECT id FROM payment_transactions WHERE mpesa_receipt_number = ? LIMIT 1
      `).bind(cleanRef).first();
      if (duplicate) {
        return jsonError("This M-Pesa transaction reference has already been submitted.", 409);
      }
      const paymentTxId = generateId("pmt");
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, mpesa_receipt_number, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_manual', ?, 'pending', 'Submitted by user, awaiting admin audit', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, cleanRef, now).run();
      await env.DB.prepare(`
        DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'
      `).bind(user.id).run();
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'pending_verification', ?)
      `).bind(userPackageId, user.id, pkg.id, now).run();
      return jsonSuccess({
        message: `M-Pesa reference ${cleanRef} submitted for ${pkg.name}! Our administrator will verify the payment code to activate your account.`,
        package: pkg,
        reference: cleanRef,
        status: "pending_verification"
      }, 201);
    }
  } catch (err) {
    console.error("Package activation error:", err);
    return jsonError("Failed to process package activation. Please try again.", 500);
  }
}
__name(onRequestPost13, "onRequestPost");

// api/products-posts.js
async function onRequestGet16(context) {
  const { env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
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
    }, 200, {
      "Cache-Control": "public, max-age=60, s-maxage=300, stale-while-revalidate=600"
    });
  } catch (err) {
    console.error("Fetch product posts error:", err);
    return jsonError("Failed to fetch promotional WhatsApp product posts", 500);
  }
}
__name(onRequestGet16, "onRequestGet");
async function onRequestPost14(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const targetId = body?.id || body?.postId;
  if (!targetId) {
    return jsonError("Product ID is required", 400);
  }
  try {
    const authUser = await authenticate(request, env).catch(() => null);
    if (authUser) {
      const pkgState = await syncAndGetUserPackageState(env.DB, authUser.id);
      if (pkgState.isTrialExpiredLockout) {
        return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: "TRIAL_EXPIRED" });
      }
    }
    await env.DB.prepare(`
      UPDATE product_posts
      SET downloads_count = downloads_count + 1
      WHERE id = ?
    `).bind(targetId).run();
    return jsonSuccess({ message: "Download tracked successfully" });
  } catch (err) {
    return jsonError("Failed to track download event", 500);
  }
}
__name(onRequestPost14, "onRequestPost");

// api/referrals.js
async function onRequestGet17(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let referralCode = user.referralCode;
  if (!referralCode) {
    try {
      const dbUser = await env.DB.prepare("SELECT referral_code FROM users WHERE id = ?").bind(user.id).first();
      referralCode = dbUser?.referral_code;
    } catch (e) {
      console.warn("Failed to query user referral_code:", e);
    }
    if (!referralCode) {
      referralCode = "ALM" + user.id.replace(/[^a-zA-Z0-9]/g, "").substring(0, 6).toUpperCase();
      try {
        await env.DB.prepare("UPDATE users SET referral_code = ? WHERE id = ?").bind(referralCode, user.id).run();
      } catch (e) {
        console.warn("Failed to persist user referral_code:", e);
      }
    }
  }
  let totalInvited = 0;
  let activePaidCount = 0;
  let totalEarningsKsh = 0;
  try {
    const summary = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_invited,
        COUNT(CASE WHEN status = 'active_paid' THEN 1 END) as active_paid_count,
        COALESCE(SUM(CASE WHEN status = 'active_paid' THEN commission_amount_ksh ELSE 0 END), 0) as total_earnings_ksh
      FROM referrals
      WHERE referrer_id = ?
    `).bind(user.id).first();
    if (summary) {
      totalInvited = summary.total_invited || 0;
      activePaidCount = summary.active_paid_count || 0;
      totalEarningsKsh = summary.total_earnings_ksh || 0;
    }
  } catch (err) {
    console.warn("Referrals summary query fallback:", err);
  }
  let activeReferrals = [];
  try {
    const activeRows = await env.DB.prepare(`
      SELECT 
        r.id,
        r.referred_user_id,
        u.name as downline_name,
        u.phone as downline_phone,
        u.email as downline_email,
        r.status,
        r.package_id,
        r.package_name,
        r.package_price_ksh,
        r.commission_rate,
        r.commission_amount_ksh,
        r.created_at,
        r.activated_at
      FROM referrals r
      JOIN users u ON r.referred_user_id = u.id
      WHERE r.referrer_id = ? AND r.status = 'active_paid'
      ORDER BY r.activated_at DESC
      LIMIT 100
    `).bind(user.id).all();
    activeReferrals = activeRows?.results || [];
  } catch (err) {
    console.warn("Active referrals query fallback:", err);
  }
  let allReferrals = [];
  try {
    const allRows = await env.DB.prepare(`
      SELECT 
        r.id,
        r.referred_user_id,
        u.name as downline_name,
        u.phone as downline_phone,
        r.status,
        r.package_name,
        r.package_price_ksh,
        r.commission_amount_ksh,
        r.created_at,
        r.activated_at
      FROM referrals r
      JOIN users u ON r.referred_user_id = u.id
      WHERE r.referrer_id = ?
      ORDER BY (CASE WHEN r.status = 'active_paid' THEN 0 ELSE 1 END), r.created_at DESC
      LIMIT 100
    `).bind(user.id).all();
    allReferrals = allRows?.results || [];
  } catch (err) {
    console.warn("All referrals query fallback:", err);
  }
  let withdrawableReferralsKsh = 0;
  try {
    const wal = await env.DB.prepare("SELECT referrals_balance_ksh FROM wallets WHERE user_id = ?").bind(user.id).first();
    withdrawableReferralsKsh = wal?.referrals_balance_ksh || 0;
  } catch (err) {
    withdrawableReferralsKsh = totalEarningsKsh;
  }
  return jsonSuccess({
    referralCode,
    commissionRatePercent: 45,
    totalInvited,
    activePaidCount,
    totalEarningsKsh,
    withdrawableReferralsKsh,
    minWithdrawalReferralsKsh: 1200,
    activeReferrals: activeReferrals || [],
    allReferrals: allReferrals || []
  });
}
__name(onRequestGet17, "onRequestGet");

// api/setup-admin.js
async function onRequestPost15(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { email, setupSecret } = body;
  if (!email || !setupSecret) {
    return jsonError("Both target user email and setupSecret are required", 400);
  }
  const configuredSecret = env.ADMIN_SETUP_SECRET;
  if (!configuredSecret) {
    return jsonError("ADMIN_SETUP_SECRET has not been set in Cloudflare environment secrets. Administrator promotion is locked.", 403);
  }
  if (setupSecret !== configuredSecret) {
    return jsonError("Invalid administrator setup secret key", 401);
  }
  try {
    const cleanEmail = email.trim().toLowerCase();
    if (cleanEmail !== "mentorbravin@gmail.com") {
      return jsonError("Only the designated administrator email (mentorbravin@gmail.com) can hold administrator privileges.", 403);
    }
    const user = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE email = ?").bind(cleanEmail).first();
    if (!user) {
      return jsonError(`No registered user found with email ${cleanEmail}. Please register the account first.`, 404);
    }
    if (user.role === "admin") {
      return jsonSuccess({ message: `User ${cleanEmail} is already an administrator.` });
    }
    await env.DB.prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?").bind(Math.floor(Date.now() / 1e3), user.id).run();
    return jsonSuccess({
      message: `User ${user.name} (${cleanEmail}) has been successfully promoted to Administrator!`,
      userId: user.id,
      role: "admin"
    });
  } catch (err) {
    console.error("Setup admin error:", err);
    return jsonError("Failed to promote user to administrator", 500);
  }
}
__name(onRequestPost15, "onRequestPost");

// api/surveys.js
var SEED_SURVEYS = [
  {
    id: "srv_saf_mpesa_2026",
    title: "Safaricom M-Pesa & Mobile Banking Consumer Pulse",
    category: "Telecom & Fintech",
    description: "Share your daily mobile money habits, Fuliza usage, and merchant Till preferences to help Kenyan fintechs improve zero-fee transfers.",
    reward_ksh: 80,
    estimated_minutes: 3,
    questions: JSON.stringify([
      {
        id: "q1",
        text: "How frequently do you use Safaricom M-Pesa to pay for daily items (Till / Paybill)?",
        options: ["Multiple times daily", "Once daily", "2-4 times a week", "Rarely / Cash preferred"]
      },
      {
        id: "q2",
        text: "Have you used M-Pesa Fuliza or overdraft services in the past 30 days?",
        options: ["Yes, regularly for emergencies", "Yes, once or twice", "No, never used Fuliza", "Prefer mobile loans (Tala / Branch)"]
      },
      {
        id: "q3",
        text: "What feature would you like to see improved most on the M-Pesa Super App?",
        options: ["Lower transaction fees", "Zero data charges without bundles", "Better expense tracking & budgeting", "Faster customer care resolution"]
      },
      {
        id: "q4",
        text: "Would you consider using Airtel Money if transaction fees were 50% lower than M-Pesa?",
        options: ["Definitely yes, already using both", "Probably yes if merchants accept it", "Unlikely, M-Pesa is universally accepted", "Not interested"]
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5e3
  },
  {
    id: "srv_ecommerce_delivery",
    title: "Kenya E-Commerce & Rapid Delivery (Jumia, Glovo & Kilimall)",
    category: "E-Commerce & Logistics",
    description: "Voice your experience regarding doorstep delivery times, package safety, and cash on delivery vs M-Pesa online prepayments.",
    reward_ksh: 70,
    estimated_minutes: 3,
    questions: JSON.stringify([
      {
        id: "q1",
        text: "Which online shopping platform do you shop with most often in Kenya?",
        options: ["Jumia Kenya", "Kilimall", "Glovo / Uber Eats for quick essentials", "Social media (Instagram / WhatsApp / TikTok sellers)", "None"]
      },
      {
        id: "q2",
        text: "What is your preferred payment method when ordering items online?",
        options: ["M-Pesa payment upon physical delivery", "Instant M-Pesa STK Push during checkout", "Credit / Debit Card", "Cash on Delivery"]
      },
      {
        id: "q3",
        text: "What is the most frustrating issue you experience with Kenyan online shopping?",
        options: ["Delivery takes too long / missed timelines", "Item received looks different from website photos", "High delivery shipping fees outside Nairobi", "Complicated return and refund processes"]
      },
      {
        id: "q4",
        text: "What is the maximum you are willing to pay for same-day delivery within your county?",
        options: ["Free delivery only", "KSh 100 - KSh 150", "KSh 200 - KSh 350", "KSh 400+ for guaranteed within 2 hours"]
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5e3
  },
  {
    id: "srv_home_internet_5g",
    title: "Smartphone & 4G/5G Home Internet Usage Trends",
    category: "Tech & Connectivity",
    description: "Help Kenyan internet service providers design affordable Wi-Fi and 5G wireless router packages for residential homes.",
    reward_ksh: 60,
    estimated_minutes: 2,
    questions: JSON.stringify([
      {
        id: "q1",
        text: "What is your primary internet connection at home?",
        options: ["Home Fiber (Safaricom, Zuku, Faiba)", "5G / 4G Wi-Fi Wireless Router", "Daily / Weekly mobile phone data bundles", "Office / Public Wi-Fi"]
      },
      {
        id: "q2",
        text: "Approximately how much do you spend monthly on all internet services combined?",
        options: ["Under KSh 1,000", "KSh 1,000 - KSh 2,500", "KSh 2,500 - KSh 4,500", "Over KSh 5,000"]
      },
      {
        id: "q3",
        text: "What do you use the highest percentage of your internet bandwidth for?",
        options: ["WhatsApp & Social media videos (TikTok / Instagram / YouTube)", "Remote work, video meetings & freelancing", "Online TV streaming (Netflix / Showmax / DSTV)", "Online studies & research"]
      },
      {
        id: "q4",
        text: "Which smartphone brand are you currently using as your primary device?",
        options: ["Samsung", "Transsion (Tecno / Infinix / Itel)", "Xiaomi / Redmi", "Apple iPhone", "Oppo / Vivo / Realme"]
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5e3
  },
  {
    id: "srv_digital_loans_hustler",
    title: "Digital Micro-Loans & Mobile Credit Preferences",
    category: "Financial Services",
    description: "Evaluate loan access, interest rates, repayment periods, and borrowing behavior among Kenyan creators and digital entrepreneurs.",
    reward_ksh: 90,
    estimated_minutes: 4,
    questions: JSON.stringify([
      {
        id: "q1",
        text: "Which mobile lending service have you used in the last 6 months?",
        options: ["Hustler Fund", "M-Shwari / KCB M-Pesa", "Digital apps (Tala, Branch, Zenka)", "Bank mobile apps (Equity, Co-op)", "Have not borrowed from mobile lenders"]
      },
      {
        id: "q2",
        text: "What is your primary reason for taking a mobile digital loan?",
        options: ["Business inventory / working capital", "Household emergencies / medical", "School fees or rent assistance", "Airtime / personal utilities", "Never borrow"]
      },
      {
        id: "q3",
        text: "What loan repayment duration works best for your cash flow?",
        options: ["Daily or 14-day cycle", "30-day single installment", "3 to 6 months flexible monthly installments", "12+ months long-term"]
      },
      {
        id: "q4",
        text: "How satisfied are you with interest rates and processing fees on Kenyan digital loans?",
        options: ["Fair & affordable (e.g. Hustler Fund)", "Acceptable for quick emergencies", "Too high / predatory interest rates", "Prefer saving in SACCO / Chamas instead"]
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5e3
  },
  {
    id: "srv_fmcg_supermarkets",
    title: "Daily FMCG & Packaged Foods Brand Loyalty",
    category: "Retail & Household",
    description: "Tell top manufacturers your choices on household maize flour, milk, cooking oil, and soap to guide supermarket pricing.",
    reward_ksh: 50,
    estimated_minutes: 2,
    questions: JSON.stringify([
      {
        id: "q1",
        text: "Where do you purchase the majority of your household groceries?",
        options: ["Local neighborhood kiosk / Duka", "Large Supermarkets (Naivas, Quickmart, Carrefour)", "Open-air county food market (Marikiti)", "Online grocery delivery apps"]
      },
      {
        id: "q2",
        text: "When buying maize flour (Unga wa Sembe), which brand do you trust most?",
        options: ["Jogoo", "Raha / Pembe", "Hostess / Soko", "Taifa / Ndovu", "Local Posho Mill flour"]
      },
      {
        id: "q3",
        text: "What factor most strongly influences your choice when buying cooking oil?",
        options: ["Price & volume offers / discounts", "Health benefits (Cholesterol free / Fortified with vitamins)", "Familiar brand reputation (Elianto, Rina, Fresh Fri)", "Packaging convenience"]
      },
      {
        id: "q4",
        text: "How has inflation impacted your monthly household shopping basket this year?",
        options: ["Switched to more affordable alternative brands", "Reduced quantities purchased per trip", "Shopping habits remained the same", "Started buying in bulk wholesale to save"]
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5e3
  }
];
async function ensureSurveysSchema(env) {
  try {
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS surveys (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Consumer Habits',
        description TEXT NOT NULL,
        reward_ksh INTEGER NOT NULL DEFAULT 60,
        estimated_minutes INTEGER NOT NULL DEFAULT 3,
        questions TEXT NOT NULL,
        target_package_id TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        completions_count INTEGER NOT NULL DEFAULT 0,
        max_completions INTEGER DEFAULT 5000,
        created_at INTEGER NOT NULL
      )
    `).run().catch(() => {
    });
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS survey_responses (
        id TEXT PRIMARY KEY,
        survey_id TEXT NOT NULL REFERENCES surveys(id),
        user_id TEXT NOT NULL REFERENCES users(id),
        answers TEXT NOT NULL,
        reward_amount_ksh INTEGER NOT NULL,
        completed_at INTEGER NOT NULL,
        UNIQUE(survey_id, user_id)
      )
    `).run().catch(() => {
    });
    const countRow = await env.DB.prepare("SELECT COUNT(*) as cnt FROM surveys").first().catch(() => null);
    if (!countRow || countRow.cnt === 0) {
      const now = Math.floor(Date.now() / 1e3);
      for (const s of SEED_SURVEYS) {
        await env.DB.prepare(`
          INSERT INTO surveys (id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          s.id,
          s.title,
          s.category,
          s.description,
          s.reward_ksh,
          s.estimated_minutes,
          s.questions,
          s.target_package_id,
          s.is_active,
          s.completions_count,
          s.max_completions,
          now
        ).run().catch(() => {
        });
      }
    }
  } catch (e) {
    console.error("ensureSurveysSchema error:", e);
  }
}
__name(ensureSurveysSchema, "ensureSurveysSchema");
async function onRequestGet18(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    await ensureSurveysSchema(env);
    const { results: userResponses } = await env.DB.prepare(`
      SELECT survey_id, reward_amount_ksh, completed_at
      FROM survey_responses
      WHERE user_id = ?
    `).bind(user.id).all();
    const completedMap = /* @__PURE__ */ new Map();
    let totalSurveyEarningsKsh = 0;
    if (userResponses && userResponses.length > 0) {
      for (const r of userResponses) {
        completedMap.set(r.survey_id, {
          completedAt: r.completed_at,
          rewardAmountKsh: r.reward_amount_ksh
        });
        totalSurveyEarningsKsh += Number(r.reward_amount_ksh || 0);
      }
    }
    const { results: surveyRows } = await env.DB.prepare(`
      SELECT id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at
      FROM surveys
      WHERE is_active = 1
      ORDER BY created_at DESC
    `).all();
    const wallet = await env.DB.prepare(`
      SELECT surveys_balance_ksh, available_balance_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first().catch(() => null);
    const surveysBalanceKsh = wallet ? Number(wallet.surveys_balance_ksh || 0) : 0;
    let availableCount = 0;
    const formattedSurveys = (surveyRows || []).map((row) => {
      let parsedQuestions = [];
      try {
        parsedQuestions = JSON.parse(row.questions);
      } catch (e) {
        parsedQuestions = [];
      }
      const userCompletion = completedMap.get(row.id);
      const isCompleted = Boolean(userCompletion);
      if (!isCompleted) {
        availableCount++;
      }
      return {
        id: row.id,
        title: row.title,
        category: row.category,
        description: row.description,
        rewardKsh: row.reward_ksh,
        estimatedMinutes: row.estimated_minutes,
        questionsCount: parsedQuestions.length,
        questions: parsedQuestions,
        // Frontend will render these when user opens survey
        completionsCount: row.completions_count,
        maxCompletions: row.max_completions,
        isCompleted,
        completedAt: userCompletion ? userCompletion.completedAt : null,
        userEarnedRewardKsh: userCompletion ? userCompletion.rewardAmountKsh : null
      };
    });
    return jsonSuccess({
      surveys: formattedSurveys,
      isTrialExpiredLockout: pkgState.isTrialExpiredLockout,
      stats: {
        surveysBalanceKsh,
        availableSurveysCount: availableCount,
        completedSurveysCount: completedMap.size,
        totalSurveyEarningsKsh
      }
    });
  } catch (err) {
    console.error("Fetch surveys error:", err);
    return jsonError("Failed to load surveys", 500);
  }
}
__name(onRequestGet18, "onRequestGet");
async function onRequestPost16(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { surveyId, answers } = body;
  if (!surveyId) {
    return jsonError("surveyId is required", 400);
  }
  if (!answers || typeof answers !== "object" || Array.isArray(answers) || Object.keys(answers).length === 0) {
    return jsonError("Please provide your answers for all survey questions", 400);
  }
  try {
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    if (pkgState.isTrialExpiredLockout) {
      return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: "TRIAL_EXPIRED" });
    }
    await ensureSurveysSchema(env);
    const survey = await env.DB.prepare(`
      SELECT id, title, reward_ksh, questions, is_active, completions_count, max_completions
      FROM surveys
      WHERE id = ?
      LIMIT 1
    `).bind(surveyId).first();
    if (!survey) {
      return jsonError("Survey campaign not found", 404);
    }
    if (survey.is_active !== 1) {
      return jsonError("This survey campaign has expired or been paused by the sponsor.", 400);
    }
    if (survey.max_completions && survey.completions_count >= survey.max_completions) {
      return jsonError("This survey campaign has reached its maximum respondent capacity.", 400);
    }
    const existing = await env.DB.prepare(`
      SELECT id, completed_at, reward_amount_ksh
      FROM survey_responses
      WHERE survey_id = ? AND user_id = ?
      LIMIT 1
    `).bind(surveyId, user.id).first();
    if (existing) {
      return jsonError("You have already completed this survey and received your payout reward.", 409);
    }
    let parsedQuestions = [];
    try {
      parsedQuestions = JSON.parse(survey.questions);
    } catch (e) {
      parsedQuestions = [];
    }
    for (const q of parsedQuestions) {
      const ans = answers[q.id];
      if (!ans || typeof ans !== "string" || !ans.trim()) {
        return jsonError(`Please answer question: "${q.text}"`, 400);
      }
    }
    const rewardKsh = Math.max(1, parseInt(survey.reward_ksh, 10) || 50);
    const now = Math.floor(Date.now() / 1e3);
    const responseId = generateId("sr");
    const txId = generateId("wtx");
    let wallet = await env.DB.prepare(`
      SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, lifetime_earnings_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();
    if (!wallet) {
      const walId = generateId("wal");
      await env.DB.prepare(`
        INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
        VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
      `).bind(walId, user.id, now).run().catch(() => {
      });
      wallet = await env.DB.prepare(`
        SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, lifetime_earnings_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    }
    const insertRes = await env.DB.prepare(`
      INSERT INTO survey_responses (id, survey_id, user_id, answers, reward_amount_ksh, completed_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      responseId,
      surveyId,
      user.id,
      JSON.stringify(answers),
      rewardKsh,
      now
    ).run();
    if (!insertRes.success) {
      return jsonError("Failed to record survey response. Please try again.", 500);
    }
    await env.DB.prepare(`
      UPDATE surveys
      SET completions_count = completions_count + 1
      WHERE id = ?
    `).bind(surveyId).run().catch(() => {
    });
    const currentSurveysBal = Number(wallet?.surveys_balance_ksh || 0);
    const currentAvailBal = Number(wallet?.available_balance_ksh || 0);
    const currentViewsBal = Number(wallet?.views_balance_ksh || 0);
    const currentRefBal = Number(wallet?.referrals_balance_ksh || 0);
    const currentLifetime = Number(wallet?.lifetime_earnings_ksh || 0);
    const nextSurveysBal = currentSurveysBal + rewardKsh;
    const nextAvailBal = currentAvailBal + rewardKsh;
    const nextLifetime = currentLifetime + rewardKsh;
    await env.DB.prepare(`
      UPDATE wallets
      SET surveys_balance_ksh = surveys_balance_ksh + ?,
          available_balance_ksh = available_balance_ksh + ?,
          lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
          updated_at = ?
      WHERE user_id = ?
    `).bind(rewardKsh, rewardKsh, rewardKsh, now, user.id).run();
    await env.DB.prepare(`
      INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
      VALUES (?, ?, ?, 'survey_reward', ?, ?, ?, ?, ?)
    `).bind(
      txId,
      wallet.id,
      user.id,
      rewardKsh,
      nextAvailBal,
      responseId,
      `Paid Survey Reward: ${survey.title} (+KSh ${rewardKsh})`,
      now
    ).run().catch(async (e) => {
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        rewardKsh,
        nextAvailBal,
        responseId,
        `Paid Survey Reward: ${survey.title} (+KSh ${rewardKsh})`,
        now
      ).run().catch(() => {
      });
    });
    return jsonSuccess({
      message: `\u{1F389} Congratulations! You have successfully completed the survey. KSh ${rewardKsh.toLocaleString()} has been credited to your Surveys Balance!`,
      rewardAmountKsh: rewardKsh,
      surveyId,
      surveyTitle: survey.title,
      completedAt: now,
      wallet: {
        surveysBalanceKsh: nextSurveysBal,
        viewsBalanceKsh: currentViewsBal,
        referralsBalanceKsh: currentRefBal,
        availableBalanceKsh: nextAvailBal
      }
    });
  } catch (err) {
    console.error("Submit survey error:", err);
    return jsonError("Failed to submit survey. Please try again.", 500);
  }
}
__name(onRequestPost16, "onRequestPost");

// api/tasks.js
async function onRequestGet19(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    const { results: campaigns } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, target_link, guidelines
      FROM campaigns
      WHERE status = 'active'
      ORDER BY created_at DESC
    `).all();
    const { results: submissions } = await env.DB.prepare(`
      SELECT ts.id, ts.reported_views, ts.approved_views, ts.reward_rate_ksh,
             ts.reward_amount_ksh, ts.evidence_text, ts.evidence_id, ts.status,
             ts.admin_notes, ts.created_at, ts.reviewed_at,
             c.title as campaign_title, c.brand_name
      FROM task_submissions ts
      LEFT JOIN campaigns c ON ts.campaign_id = c.id
      WHERE ts.user_id = ?
      ORDER BY ts.created_at DESC
      LIMIT 20
    `).bind(user.id).all();
    const now = Math.floor(Date.now() / 1e3);
    const latest = (submissions || []).find((s) => s.evidence_id !== null && s.evidence_id !== void 0) || null;
    const userRow = await env.DB.prepare("SELECT COALESCE(submission_tickets, 0) as submission_tickets FROM users WHERE id = ?").bind(user.id).first().catch(() => null);
    const submissionTickets = userRow ? userRow.submission_tickets || 0 : 0;
    let canSubmit = true;
    let secondsRemaining = 0;
    let nextAllowedAt = now;
    let waivedByTicket = false;
    if (latest) {
      const cooldownSeconds = 18 * 60 * 60;
      const nextTime = latest.created_at + cooldownSeconds;
      if (now < nextTime) {
        secondsRemaining = nextTime - now;
        nextAllowedAt = nextTime;
        if (submissionTickets > 0) {
          canSubmit = true;
          waivedByTicket = true;
        } else {
          canSubmit = false;
        }
      }
    }
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id, now);
    return jsonSuccess({
      campaigns: campaigns || [],
      submissions: submissions || [],
      packageState: {
        hasActivePackage: Boolean(pkgState.activePackage),
        isTrialActive: pkgState.isTrialActive,
        trialSecondsRemaining: pkgState.trialSecondsRemaining,
        isTrialExpiredLockout: pkgState.isTrialExpiredLockout
      },
      cooldown: {
        canSubmit,
        secondsRemaining,
        nextAllowedAt,
        lastSubmittedAt: latest ? latest.created_at : null,
        waivedByTicket,
        submissionTickets
      }
    });
  } catch (err) {
    console.error("Fetch tasks error:", err);
    return jsonError("Failed to fetch task submissions and campaigns", 500);
  }
}
__name(onRequestGet19, "onRequestGet");
async function onRequestPost17(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { campaignId, reportedViews, evidenceBase64, evidenceNote, fileName, fileType } = body;
  const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
  const activePackage = pkgState.activePackage;
  if (!activePackage) {
    if (pkgState.isTrialExpiredLockout) {
      return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: "TRIAL_EXPIRED" });
    }
    return jsonError("You do not have an active advertising partner package. Please activate the 1-Day Free Trial or a paid partner package first.", 403);
  }
  const views = parseInt(reportedViews, 10);
  if (isNaN(views) || views <= 0) {
    return jsonError("Please enter a valid number of reported WhatsApp Status views (minimum 1 view)", 400);
  }
  if (views > 1e4) {
    return jsonError("Reported views exceeds maximum allowable threshold for verification", 400);
  }
  const now = Math.floor(Date.now() / 1e3);
  const userRow = await env.DB.prepare("SELECT COALESCE(submission_tickets, 0) as submission_tickets FROM users WHERE id = ?").bind(user.id).first().catch(() => null);
  const submissionTickets = userRow ? userRow.submission_tickets || 0 : 0;
  const latestSubmission = await env.DB.prepare(`
    SELECT created_at FROM task_submissions WHERE user_id = ? AND evidence_id IS NOT NULL ORDER BY created_at DESC LIMIT 1
  `).bind(user.id).first();
  let ticketUsed = false;
  if (latestSubmission) {
    const elapsed = now - latestSubmission.created_at;
    const cooldownDuration = 18 * 60 * 60;
    if (elapsed < cooldownDuration) {
      if (submissionTickets > 0) {
        ticketUsed = true;
        await env.DB.prepare("UPDATE users SET submission_tickets = MAX(0, submission_tickets - 1), updated_at = ? WHERE id = ?").bind(now, user.id).run().catch(() => {
        });
      } else {
        const waitMinutes = Math.ceil((cooldownDuration - elapsed) / 60);
        const waitHours = (waitMinutes / 60).toFixed(1);
        return jsonError(`18-hour submission cooldown active. You can submit another WhatsApp task in approximately ${waitHours} hours (${waitMinutes} minutes), or contact support/admin for a submission ticket.`, 429, {
          secondsRemaining: cooldownDuration - elapsed
        });
      }
    }
  }
  if (!evidenceBase64 || typeof evidenceBase64 !== "string") {
    return jsonError("Screenshot evidence of your WhatsApp Status view count is required", 400);
  }
  if (evidenceBase64.length > 5 * 1024 * 1024) {
    return jsonError("Screenshot file size is too large. Please upload an image under 3MB.", 400);
  }
  try {
    const evidenceId = generateId("evd");
    const taskId = generateId("tsk");
    await env.DB.prepare(`
      INSERT INTO task_evidence (id, file_name, file_type, file_size, data_base64, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      evidenceId,
      fileName || "whatsapp_status_proof.png",
      fileType || "image/png",
      Math.round(evidenceBase64.length * 0.75),
      evidenceBase64,
      now
    ).run();
    const maxViews = activePackage.max_views_per_task || 200;
    const cappedViews = Math.min(views, maxViews);
    const estimatedRewardKsh = cappedViews * activePackage.reward_per_view_ksh;
    await env.DB.prepare(`
      INSERT INTO task_submissions (
        id, user_id, campaign_id, package_id, reported_views, approved_views,
        reward_rate_ksh, reward_amount_ksh, evidence_text, evidence_id,
        status, created_at, reviewed_at
      )
      VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, ?, 'pending', ?, NULL)
    `).bind(
      taskId,
      user.id,
      campaignId || "camp_almai_main",
      activePackage.package_id,
      views,
      activePackage.reward_per_view_ksh,
      evidenceNote || "WhatsApp Status views proof submitted",
      evidenceId,
      now
    ).run();
    return jsonSuccess({
      message: ticketUsed ? `Task submitted successfully! Your submission of ${views} WhatsApp views is awaiting administrator approval. (18-hour cooldown was waived using your submission ticket; ${Math.max(0, submissionTickets - 1)} ticket(s) remaining).` : `Task submitted successfully! Your submission of ${views} WhatsApp views is awaiting administrator approval. Your wallet balance will be updated once approved by an administrator.`,
      taskId,
      reportedViews: views,
      estimatedRewardKsh,
      packageRateKsh: activePackage.reward_per_view_ksh,
      status: "pending",
      ticketUsed,
      remainingTickets: ticketUsed ? Math.max(0, submissionTickets - 1) : submissionTickets
    }, 201);
  } catch (err) {
    console.error("Task submission error:", err);
    return jsonError("Failed to record task submission. Please try again.", 500);
  }
}
__name(onRequestPost17, "onRequestPost");

// api/withdrawals.js
var MINIMUM_WITHDRAWAL_KSH = 1200;
async function onRequestGet20(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    await env.DB.prepare("ALTER TABLE withdrawal_requests ADD COLUMN payment_method TEXT DEFAULT 'mpesa'").run().catch(() => {
    });
    let wallet = null;
    try {
      wallet = await env.DB.prepare(`
        SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      wallet = await env.DB.prepare(`
        SELECT available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
      if (wallet) wallet.surveys_balance_ksh = 0;
    }
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    const activePackage = pkgState.activePackage;
    const { results: requests } = await env.DB.prepare(`
      SELECT id, amount_ksh, phone_number, status, balance_type, mpesa_receipt_number, rejection_reason, created_at, processed_at
      FROM withdrawal_requests
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(user.id).all();
    const minViewsWithdrawal = activePackage?.min_withdrawal_views_ksh || 5e3;
    return jsonSuccess({
      wallet: wallet || { available_balance_ksh: 0, views_balance_ksh: 0, referrals_balance_ksh: 0, surveys_balance_ksh: 0, reserved_balance_ksh: 0, lifetime_withdrawn_ksh: 0 },
      activePackage: activePackage || null,
      minViewsWithdrawalKsh: minViewsWithdrawal,
      minReferralsWithdrawalKsh: MINIMUM_WITHDRAWAL_KSH,
      minSurveysWithdrawalKsh: MINIMUM_WITHDRAWAL_KSH,
      withdrawals: requests || []
    });
  } catch (err) {
    console.error("Fetch withdrawals error:", err);
    return jsonError("Failed to fetch withdrawal requests", 500);
  }
}
__name(onRequestGet20, "onRequestGet");
async function onRequestPost18(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { amountKsh, phoneNumber, balanceType: rawBalanceType, paymentMethod: rawMethod, paypalEmail } = body;
  const paymentMethod = rawMethod === "paypal" ? "paypal" : "mpesa";
  let balanceType = "views";
  if (rawBalanceType === "referrals" || rawBalanceType === "referral") {
    balanceType = "referrals";
  } else if (rawBalanceType === "surveys" || rawBalanceType === "survey") {
    balanceType = "surveys";
  }
  const amount = parseInt(amountKsh, 10);
  if (isNaN(amount) || amount <= 0) {
    return jsonError("Please enter a valid withdrawal amount", 400);
  }
  let targetDestination = "";
  if (paymentMethod === "paypal") {
    const emailCandidate = (paypalEmail || phoneNumber || "").trim();
    if (!emailCandidate || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailCandidate)) {
      return jsonError("Valid PayPal email address is required for payout", 400);
    }
    targetDestination = emailCandidate;
  } else {
    const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, "") : user.phone;
    if (!targetPhone || targetPhone.length < 9) {
      return jsonError("Valid M-Pesa phone number is required for payout", 400);
    }
    targetDestination = targetPhone;
  }
  try {
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    if (pkgState.isTrialExpiredLockout) {
      return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: "TRIAL_EXPIRED" });
    }
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {
    });
    let wallet = null;
    try {
      wallet = await env.DB.prepare(`
        SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    } catch (e) {
      wallet = await env.DB.prepare(`
        SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
      if (wallet) wallet.surveys_balance_ksh = 0;
    }
    if (!wallet) {
      return jsonError("Wallet account not found", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    const withdrawalId = generateId("wth");
    const txId = generateId("wtx");
    if (balanceType === "views") {
      const activePackage = pkgState.activePackage;
      if (!activePackage) {
        return jsonError("You must have an active partner package to withdraw status views earnings. If you have referral earnings, you can withdraw them separately.", 400);
      }
      const minViewsLimit = Math.max(MINIMUM_WITHDRAWAL_KSH, activePackage.min_withdrawal_views_ksh || 5e3);
      if (amount < minViewsLimit) {
        return jsonError(`Minimum withdrawal amount for Status Views is KSh ${minViewsLimit.toLocaleString()} (requested KSh ${amount.toLocaleString()}).`, 400);
      }
      const availableViews = typeof wallet.views_balance_ksh === "number" ? wallet.views_balance_ksh : wallet.available_balance_ksh;
      if (availableViews < amount) {
        return jsonError(`Insufficient Status Views earnings. Your available Views balance is KSh ${availableViews.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }
      const balanceAfter = wallet.available_balance_ksh - amount;
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = views_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND views_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();
      if (!updateResult.success || updateResult.meta && updateResult.meta.changes === 0) {
        return jsonError("Concurrent balance update conflict or insufficient views funds. Please refresh and try again.", 409);
      }
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, payment_method, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'views', ?, ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, paymentMethod, now).run().catch(async () => {
        await env.DB.prepare(`
          INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
          VALUES (?, ?, ?, ?, ?, 'pending', 'views', ?)
        `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, now).run();
      });
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'withdrawal_reserve', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        amount,
        balanceAfter,
        withdrawalId,
        `${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"} payout request from Status Views (${activePackage.name}) to ${targetDestination} placed on hold pending disbursement`,
        now
      ).run();
      return jsonSuccess({
        message: `Status Views payout request for KSh ${amount.toLocaleString()} submitted successfully via ${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"}. Funds have been reserved.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetDestination,
          paymentMethod,
          balanceType: "views",
          status: "pending",
          createdAt: now
        },
        wallet: {
          availableBalanceKsh: balanceAfter,
          viewsBalanceKsh: availableViews - amount,
          referralsBalanceKsh: wallet.referrals_balance_ksh || 0,
          surveysBalanceKsh: wallet.surveys_balance_ksh || 0,
          reservedBalanceKsh: wallet.reserved_balance_ksh + amount
        }
      }, 201);
    } else if (balanceType === "surveys") {
      const minSurveyLimit = MINIMUM_WITHDRAWAL_KSH;
      if (amount < minSurveyLimit) {
        return jsonError(`Minimum withdrawal amount across all company services is KSh ${minSurveyLimit.toLocaleString()}`, 400);
      }
      const availableSurveys = Number(wallet.surveys_balance_ksh || 0);
      if (availableSurveys < amount) {
        return jsonError(`Insufficient Paid Surveys earnings. Your available Surveys balance is KSh ${availableSurveys.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }
      const balanceAfter = wallet.available_balance_ksh - amount;
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET surveys_balance_ksh = surveys_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND surveys_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();
      if (!updateResult.success || updateResult.meta && updateResult.meta.changes === 0) {
        return jsonError("Concurrent balance update conflict or insufficient survey funds. Please refresh and try again.", 409);
      }
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, payment_method, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'surveys', ?, ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, paymentMethod, now).run().catch(async () => {
        await env.DB.prepare(`
          INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
          VALUES (?, ?, ?, ?, ?, 'pending', 'surveys', ?)
        `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, now).run();
      });
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'withdrawal_reserve', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        amount,
        balanceAfter,
        withdrawalId,
        `${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"} payout request from Paid Surveys to ${targetDestination} placed on hold pending disbursement`,
        now
      ).run();
      return jsonSuccess({
        message: `Paid Surveys payout request for KSh ${amount.toLocaleString()} submitted successfully via ${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"}. Funds have been reserved.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetDestination,
          paymentMethod,
          balanceType: "surveys",
          status: "pending",
          createdAt: now
        },
        wallet: {
          availableBalanceKsh: balanceAfter,
          viewsBalanceKsh: wallet.views_balance_ksh || 0,
          referralsBalanceKsh: wallet.referrals_balance_ksh || 0,
          surveysBalanceKsh: availableSurveys - amount,
          reservedBalanceKsh: wallet.reserved_balance_ksh + amount
        }
      }, 201);
    } else {
      const minReferralLimit = MINIMUM_WITHDRAWAL_KSH;
      if (amount < minReferralLimit) {
        return jsonError(`Minimum withdrawal amount across all company services is KSh ${minReferralLimit.toLocaleString()}`, 400);
      }
      const availableReferrals = wallet.referrals_balance_ksh || 0;
      if (availableReferrals < amount) {
        return jsonError(`Insufficient Referral Commission funds. Your available Referral balance is KSh ${availableReferrals.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }
      const balanceAfter = wallet.available_balance_ksh - amount;
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET referrals_balance_ksh = referrals_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND referrals_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();
      if (!updateResult.success || updateResult.meta && updateResult.meta.changes === 0) {
        return jsonError("Concurrent balance update conflict or insufficient referral funds. Please refresh and try again.", 409);
      }
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, payment_method, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'referrals', ?, ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, paymentMethod, now).run().catch(async () => {
        await env.DB.prepare(`
          INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
          VALUES (?, ?, ?, ?, ?, 'pending', 'referrals', ?)
        `).bind(withdrawalId, user.id, wallet.id, amount, targetDestination, now).run();
      });
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'withdrawal_reserve', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        amount,
        balanceAfter,
        withdrawalId,
        `${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"} payout request from Referral Commissions to ${targetDestination} placed on hold pending disbursement`,
        now
      ).run();
      return jsonSuccess({
        message: `Referral Commission payout request for KSh ${amount.toLocaleString()} submitted successfully via ${paymentMethod === "paypal" ? "PayPal" : "M-Pesa"}. Funds have been reserved.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetDestination,
          paymentMethod,
          balanceType: "referrals",
          status: "pending",
          createdAt: now
        },
        wallet: {
          availableBalanceKsh: balanceAfter,
          viewsBalanceKsh: wallet.views_balance_ksh || 0,
          referralsBalanceKsh: availableReferrals - amount,
          surveysBalanceKsh: wallet.surveys_balance_ksh || 0,
          reservedBalanceKsh: wallet.reserved_balance_ksh + amount
        }
      }, 201);
    }
  } catch (err) {
    console.error("Withdrawal error:", err);
    return jsonError("Failed to process withdrawal request. Please try again.", 500);
  }
}
__name(onRequestPost18, "onRequestPost");

// ../.wrangler/tmp/pages-IfJYCY/functionsRoutes-0.7428331975922463.mjs
var routes = [
  {
    routePath: "/api/admin/audit-logs",
    mountPath: "/api/admin",
    method: "DELETE",
    middlewares: [],
    modules: [onRequestDelete]
  },
  {
    routePath: "/api/admin/audit-logs",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet]
  },
  {
    routePath: "/api/admin/bonuses",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet2]
  },
  {
    routePath: "/api/admin/bonuses",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost]
  },
  {
    routePath: "/api/admin/cleanup",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet3]
  },
  {
    routePath: "/api/admin/cleanup",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost2]
  },
  {
    routePath: "/api/admin/packages",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet4]
  },
  {
    routePath: "/api/admin/packages",
    mountPath: "/api/admin",
    method: "PUT",
    middlewares: [],
    modules: [onRequestPut]
  },
  {
    routePath: "/api/admin/payments",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet5]
  },
  {
    routePath: "/api/admin/payments",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost3]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "DELETE",
    middlewares: [],
    modules: [onRequestDelete2]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet6]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost4]
  },
  {
    routePath: "/api/admin/stats",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet7]
  },
  {
    routePath: "/api/admin/surveys",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet8]
  },
  {
    routePath: "/api/admin/surveys",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost5]
  },
  {
    routePath: "/api/admin/tasks",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet9]
  },
  {
    routePath: "/api/admin/tasks",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost6]
  },
  {
    routePath: "/api/admin/users",
    mountPath: "/api/admin",
    method: "DELETE",
    middlewares: [],
    modules: [onRequestDelete3]
  },
  {
    routePath: "/api/admin/users",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet10]
  },
  {
    routePath: "/api/admin/users",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost7]
  },
  {
    routePath: "/api/admin/withdrawals",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet11]
  },
  {
    routePath: "/api/admin/withdrawals",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost8]
  },
  {
    routePath: "/api/auth/login",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost9]
  },
  {
    routePath: "/api/auth/logout",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost10]
  },
  {
    routePath: "/api/auth/me",
    mountPath: "/api/auth",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet12]
  },
  {
    routePath: "/api/auth/register",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost11]
  },
  {
    routePath: "/api/evidence/:id",
    mountPath: "/api/evidence",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet13]
  },
  {
    routePath: "/api/inquiries",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet14]
  },
  {
    routePath: "/api/inquiries",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost12]
  },
  {
    routePath: "/api/packages",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet15]
  },
  {
    routePath: "/api/packages",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost13]
  },
  {
    routePath: "/api/products-posts",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet16]
  },
  {
    routePath: "/api/products-posts",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost14]
  },
  {
    routePath: "/api/referrals",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet17]
  },
  {
    routePath: "/api/setup-admin",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost15]
  },
  {
    routePath: "/api/surveys",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet18]
  },
  {
    routePath: "/api/surveys",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost16]
  },
  {
    routePath: "/api/tasks",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet19]
  },
  {
    routePath: "/api/tasks",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost17]
  },
  {
    routePath: "/api/withdrawals",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet20]
  },
  {
    routePath: "/api/withdrawals",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost18]
  }
];

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: /* @__PURE__ */ __name(() => {
            isFailOpen = true;
          }, "passThroughOnException")
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    }, "next");
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_worker_default as default
};
