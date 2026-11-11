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

