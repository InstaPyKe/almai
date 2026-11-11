import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

import { onRequestPost as registerPost } from '../functions/api/auth/register.js';
import { onRequestPost as loginPost } from '../functions/api/auth/login.js';
import { verifyRecaptchaToken } from '../functions/api/_utils.js';

function createD1Wrapper(sqliteDb) {
  return {
    prepare(sql) {
      return {
        bind(...args) {
          return {
            async first() {
              return sqliteDb.prepare(sql).get(...args) ?? null;
            },
            async all() {
              return { results: sqliteDb.prepare(sql).all(...args) };
            },
            async run() {
              const info = sqliteDb.prepare(sql).run(...args);
              return { success: true, meta: { changes: Number(info.changes || 0) } };
            }
          };
        },
        async first() {
          return sqliteDb.prepare(sql).get() ?? null;
        },
        async all() {
          return { results: sqliteDb.prepare(sql).all() };
        },
        async run() {
          const info = sqliteDb.prepare(sql).run();
          return { success: true, meta: { changes: Number(info.changes || 0) } };
        }
      };
    }
  };
}

function setupAuthEnv(verifyFn) {
  const sqliteDb = new DatabaseSync(':memory:');
  const baseSql = fs.readFileSync('migrations/0001_initial_schema.sql', 'utf8');
  sqliteDb.exec(baseSql);

  for (const extra of [
    'migrations/0005_referral_system.sql',
    'migrations/0006_package_withdrawal_limits_and_referral_balance.sql'
  ]) {
    if (fs.existsSync(extra)) {
      const sql = fs.readFileSync(extra, 'utf8');
      for (const stmt of sql.split(/;\s*\r?\n/)) {
        const clean = stmt.trim();
        if (clean) {
          try { sqliteDb.exec(clean); } catch (_) {}
        }
      }
    }
  }

  return {
    sqliteDb,
    env: {
      DB: createD1Wrapper(sqliteDb),
      RECAPTCHA_SECRET_KEY: '6LfdzhouAAAAAJRNP6vfgi_QCLbd6q0-c73a6bi2',
      RECAPTCHA_VERIFY_FN: verifyFn
    }
  };
}

function postReq(url, body) {
  return new Request(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'cf-connecting-ip': '197.232.10.20' },
    body: JSON.stringify(body)
  });
}

test('Google reCAPTCHA enforces token verification on register and login', async () => {
  const seenCalls = [];
  const { env } = setupAuthEnv(async ({ secret, response, remoteip }) => {
    seenCalls.push({ secret, response, remoteip });
    if (response === 'valid_token_123') {
      return { success: true };
    }
    return { success: false, 'error-codes': ['invalid-input-response'] };
  });

  // 1. Direct helper check for missing token
  const missingRes = await verifyRecaptchaToken('', '1.2.3.4', env);
  assert.equal(missingRes.ok, false);
  assert.equal(missingRes.status, 400);

  // 2. Register missing reCAPTCHA token -> 400
  const regMissingRes = await registerPost({
    request: postReq('http://localhost/api/auth/register', {
      name: 'Alice Partner',
      email: 'alice@example.com',
      phone: '0712345678',
      password: 'Password123!'
    }),
    env
  });
  const regMissingData = await regMissingRes.json();
  assert.equal(regMissingRes.status, 400);
  assert.equal(regMissingData.details?.recaptchaRequired, true);

  // 3. Register invalid reCAPTCHA token -> 403
  const regBadRes = await registerPost({
    request: postReq('http://localhost/api/auth/register', {
      name: 'Alice Partner',
      email: 'alice@example.com',
      phone: '0712345678',
      password: 'Password123!',
      recaptchaToken: 'bad_token'
    }),
    env
  });
  const regBadData = await regBadRes.json();
  assert.equal(regBadRes.status, 403);
  assert.equal(regBadData.details?.recaptchaRequired, true);

  // 4. Register valid reCAPTCHA token -> 201 Created
  const regOkRes = await registerPost({
    request: postReq('http://localhost/api/auth/register', {
      name: 'Alice Partner',
      email: 'alice@example.com',
      phone: '0712345678',
      password: 'Password123!',
      recaptchaToken: 'valid_token_123'
    }),
    env
  });
  assert.equal(regOkRes.status, 201);

  // 5. Login missing reCAPTCHA token -> 400 (does not consume password rate limit)
  const loginMissingRes = await loginPost({
    request: postReq('http://localhost/api/auth/login', {
      email: 'alice@example.com',
      password: 'Password123!'
    }),
    env
  });
  const loginMissingData = await loginMissingRes.json();
  assert.equal(loginMissingRes.status, 400);
  assert.equal(loginMissingData.details?.recaptchaRequired, true);

  // 6. Login invalid reCAPTCHA token -> 403
  const loginBadRes = await loginPost({
    request: postReq('http://localhost/api/auth/login', {
      email: 'alice@example.com',
      password: 'Password123!',
      recaptchaToken: 'expired_token'
    }),
    env
  });
  assert.equal(loginBadRes.status, 403);

  // 7. Login valid reCAPTCHA token -> 200 OK & session issued
  const loginOkRes = await loginPost({
    request: postReq('http://localhost/api/auth/login', {
      email: 'alice@example.com',
      password: 'Password123!',
      recaptchaToken: 'valid_token_123'
    }),
    env
  });
  const loginOkData = await loginOkRes.json();
  assert.equal(loginOkRes.status, 200);
  assert.equal(loginOkData.success, true);
  assert.ok(loginOkData.token);

  // Verify secret key passed to Google siteverify matches configured secret
  assert.ok(seenCalls.length >= 4);
  for (const call of seenCalls) {
    assert.equal(call.secret, '6LfdzhouAAAAAJRNP6vfgi_QCLbd6q0-c73a6bi2');
  }
});

test('Legacy D1 users schema without referral_code/referred_by auto-heals on login and register', async () => {
  const { hashPassword } = await import('../functions/api/_utils.js');
  const sqliteDb = new DatabaseSync(':memory:');
  sqliteDb.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT,
      password_hash TEXT, salt TEXT, role TEXT DEFAULT 'user', status TEXT DEFAULT 'active',
      created_at INTEGER, updated_at INTEGER
    );
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL, ip_address TEXT, user_agent TEXT
    );
    CREATE TABLE packages (
      id TEXT PRIMARY KEY, name TEXT, slug TEXT UNIQUE, price_ksh INTEGER,
      reward_per_view_ksh INTEGER, max_views_per_task INTEGER,
      features TEXT, badge TEXT, is_active INTEGER DEFAULT 1, created_at INTEGER
    );
    CREATE TABLE user_packages (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, package_id TEXT NOT NULL,
      status TEXT DEFAULT 'active', activated_at INTEGER, expires_at INTEGER
    );
    CREATE TABLE payment_transactions (
      id TEXT PRIMARY KEY, user_id TEXT, package_id TEXT, mpesa_receipt_number TEXT,
      status TEXT DEFAULT 'pending', created_at INTEGER
    );
    CREATE TABLE wallets (
      id TEXT PRIMARY KEY, user_id TEXT UNIQUE, available_balance_ksh INTEGER DEFAULT 0,
      reserved_balance_ksh INTEGER DEFAULT 0, lifetime_earnings_ksh INTEGER DEFAULT 0,
      lifetime_withdrawn_ksh INTEGER DEFAULT 0, updated_at INTEGER
    );
    CREATE TABLE rate_limits (
      key TEXT PRIMARY KEY, attempts INTEGER NOT NULL DEFAULT 1,
      last_attempt INTEGER NOT NULL, blocked_until INTEGER NOT NULL DEFAULT 0
    );
  `);

  const now = Math.floor(Date.now() / 1000);
  const { hash, salt } = await hashPassword('LegacyPass123!');
  sqliteDb.prepare(`
    INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
    VALUES ('usr_legacy1', 'Earlier Partner', 'legacy@example.com', '0712000111', ?, ?, 'user', 'active', ?, ?)
  `).run(hash, salt, now, now);

  const env = {
    DB: createD1Wrapper(sqliteDb),
    RECAPTCHA_VERIFY_FN: async () => ({ success: true, score: 0.9 })
  };

  // Earlier user must be able to sign in with correct password on legacy table
  const loginRes = await loginPost({
    request: postReq('http://localhost/api/auth/login', {
      email: 'legacy@example.com',
      password: 'LegacyPass123!',
      recaptchaToken: 'tok_ok'
    }),
    env
  });
  const loginData = await loginRes.json();
  assert.equal(loginRes.status, 200);
  assert.equal(loginData.success, true);
  assert.ok(loginData.user?.referralCode);

  // New user registration must also succeed without server error
  const regRes = await registerPost({
    request: postReq('http://localhost/api/auth/register', {
      name: 'New Legacy DB User',
      email: 'newcomer@example.com',
      phone: '0712999888',
      password: 'NewPassword123!',
      recaptchaToken: 'tok_ok'
    }),
    env
  });
  const regData = await regRes.json();
  assert.equal(regRes.status, 201);
  assert.equal(regData.registered, true);
});


