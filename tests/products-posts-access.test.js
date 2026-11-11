import assert from 'node:assert/strict';
import test from 'node:test';
import { DatabaseSync } from 'node:sqlite';
import { onRequestGet as productsPostsGet, onRequestPost as productsPostsPost } from '../functions/api/products-posts.js';

function createMockD1(sqliteDb) {
  return {
    prepare(sql) {
      return {
        _params: [],
        bind(...args) {
          this._params = args;
          return this;
        },
        async first() {
          const stmt = sqliteDb.prepare(sql);
          const row = stmt.get(...this._params);
          return row === undefined ? null : row;
        },
        async all() {
          const stmt = sqliteDb.prepare(sql);
          const results = stmt.all(...this._params);
          return { results };
        },
        async run() {
          const stmt = sqliteDb.prepare(sql);
          const info = stmt.run(...this._params);
          return { success: true, meta: { changes: info.changes, last_row_id: info.lastInsertRowid } };
        }
      };
    }
  };
}

function makeReq(url, method = 'GET', sessionId = null, bodyObj = null) {
  const headers = new Headers();
  if (sessionId) headers.set('Cookie', `almai_session=${sessionId}`);
  if (bodyObj !== null) headers.set('Content-Type', 'application/json');
  return new Request(url, {
    method,
    headers,
    body: bodyObj !== null ? JSON.stringify(bodyObj) : undefined
  });
}

test('GET/POST /api/products-posts restricts full daily catalog to active partners & admins, returning 3-post sample to public/inactive users', async () => {
  const sqliteDb = new DatabaseSync(':memory:');
  sqliteDb.exec(`
    CREATE TABLE users (
      id TEXT PRIMARY KEY, name TEXT, email TEXT UNIQUE, phone TEXT, password_hash TEXT,
      role TEXT DEFAULT 'user', referral_code TEXT UNIQUE, referred_by TEXT, status TEXT DEFAULT 'active', created_at INTEGER
    );
    CREATE TABLE sessions (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires_at INTEGER NOT NULL, created_at INTEGER NOT NULL
    );
    CREATE TABLE packages (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, slug TEXT UNIQUE NOT NULL, price_ksh INTEGER NOT NULL,
      reward_per_view_ksh INTEGER NOT NULL, max_views_per_task INTEGER NOT NULL,
      min_withdrawal_views_ksh INTEGER DEFAULT 5000, badge TEXT, description TEXT, features_json TEXT,
      is_active INTEGER DEFAULT 1, is_free_trial INTEGER DEFAULT 0, duration_hours INTEGER DEFAULT NULL
    );
    CREATE TABLE user_packages (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, package_id TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active',
      activated_at INTEGER, expires_at INTEGER
    );
    CREATE TABLE payment_transactions (
      id TEXT PRIMARY KEY, user_id TEXT NOT NULL, package_id TEXT NOT NULL, mpesa_receipt_number TEXT,
      amount_ksh INTEGER, phone_number TEXT, status TEXT NOT NULL DEFAULT 'pending', created_at INTEGER
    );
    CREATE TABLE product_posts (
      id TEXT PRIMARY KEY, title TEXT NOT NULL, brand_name TEXT, description TEXT, caption TEXT,
      image_url TEXT, image_base64 TEXT, image_name TEXT, downloads_count INTEGER DEFAULT 0,
      status TEXT DEFAULT 'active', created_at INTEGER DEFAULT (strftime('%s', 'now'))
    );
  `);

  const now = Math.floor(Date.now() / 1000);
  sqliteDb.prepare(`
    INSERT INTO packages (id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, min_withdrawal_views_ksh, is_active, is_free_trial, duration_hours)
    VALUES
      ('pkg_trial', '1-Day Free Trial', 'free-trial', 0, 20, 50, 5000, 1, 1, 24),
      ('pkg_starter', 'Starter Pro', 'starter-pro', 250, 20, 50, 5000, 1, 0, NULL)
  `).run();

  sqliteDb.prepare(`
    INSERT INTO users (id, name, email, phone, password_hash, role, referral_code, status, created_at)
    VALUES
      ('usr_inactive', 'No Pkg User', 'nopkg@example.com', '0711000001', 'h', 'user', 'ALM1', 'active', ?),
      ('usr_paid', 'Paid Partner', 'paid@example.com', '0711000002', 'h', 'user', 'ALM2', 'active', ?),
      ('usr_trial', 'Trial Partner', 'trial@example.com', '0711000003', 'h', 'user', 'ALM3', 'active', ?),
      ('usr_admin', 'Admin', 'mentorbravin@gmail.com', '0711000004', 'h', 'admin', 'ALM4', 'active', ?)
  `).run(now, now, now, now);

  const farExp = now + 86400 * 7;
  sqliteDb.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, created_at)
    VALUES
      ('sess_inactive', 'usr_inactive', ?, ?),
      ('sess_paid', 'usr_paid', ?, ?),
      ('sess_trial', 'usr_trial', ?, ?),
      ('sess_admin', 'usr_admin', ?, ?)
  `).run(farExp, now, farExp, now, farExp, now, farExp, now);

  sqliteDb.prepare(`
    INSERT INTO user_packages (id, user_id, package_id, status, activated_at, expires_at)
    VALUES
      ('up_paid', 'usr_paid', 'pkg_starter', 'active', ?, NULL),
      ('up_trial', 'usr_trial', 'pkg_trial', 'active', ?, ?)
  `).run(now, now, now + 86400);

  for (let i = 1; i <= 6; i++) {
    sqliteDb.prepare(`
      INSERT INTO product_posts (id, title, brand_name, caption, status, created_at)
      VALUES (?, ?, ?, ?, 'active', ?)
    `).run(`post_${i}`, `Daily Product ${i}`, `Brand ${i}`, `Caption ${i}`, now + i);
  }
  sqliteDb.prepare(`
    INSERT INTO product_posts (id, title, brand_name, caption, status, created_at)
    VALUES ('post_inactive', 'Hidden Inactive', 'Hidden', 'Should not return', 'inactive', ?)
  `).run(now + 10);

  const env = { DB: createMockD1(sqliteDb) };

  // 1. Public unauthenticated visitor receives ONLY 3 sample posts
  const publicRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts'), env });
  const publicData = await publicRes.json();
  assert.equal(publicRes.status, 200);
  assert.equal(publicData.isPublicSample, true);
  assert.equal(publicData.hasFullAccess, false);
  assert.equal(publicData.totalCount, 6);
  assert.equal(publicData.posts.length, 3);
  assert.equal(publicData.posts[0].id, 'post_6');

  // 2. Signed-in user without an active package ALSO receives ONLY 3 sample posts
  const inactiveRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts', 'GET', 'sess_inactive'), env });
  const inactiveData = await inactiveRes.json();
  assert.equal(inactiveRes.status, 200);
  assert.equal(inactiveData.isPublicSample, true);
  assert.equal(inactiveData.hasFullAccess, false);
  assert.equal(inactiveData.posts.length, 3);

  // 3. Active paid partner receives ALL 6 active posts
  const paidRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts', 'GET', 'sess_paid'), env });
  const paidData = await paidRes.json();
  assert.equal(paidRes.status, 200);
  assert.equal(paidData.isPublicSample, false);
  assert.equal(paidData.hasFullAccess, true);
  assert.equal(paidData.posts.length, 6);

  // 4. Active 1-day trial partner receives ALL 6 active posts
  const trialRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts', 'GET', 'sess_trial'), env });
  const trialData = await trialRes.json();
  assert.equal(trialData.hasFullAccess, true);
  assert.equal(trialData.posts.length, 6);

  // 5. After 1-day trial expires, user drops back to 3-post public sample
  sqliteDb.prepare(`UPDATE user_packages SET expires_at = ? WHERE id = 'up_trial'`).run(now - 60);
  const expiredRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts', 'GET', 'sess_trial'), env });
  const expiredData = await expiredRes.json();
  assert.equal(expiredData.hasFullAccess, false);
  assert.equal(expiredData.isPublicSample, true);
  assert.equal(expiredData.posts.length, 3);

  // 6. Admin always receives full active catalog
  const adminRes = await productsPostsGet({ request: makeReq('http://localhost/api/products-posts', 'GET', 'sess_admin'), env });
  const adminData = await adminRes.json();
  assert.equal(adminData.hasFullAccess, true);
  assert.equal(adminData.posts.length, 6);

  // 7. Download tracking requires active partner / admin
  const guestPostRes = await productsPostsPost({ request: makeReq('http://localhost/api/products-posts', 'POST', null, { id: 'post_6' }), env });
  assert.equal(guestPostRes.status, 401);

  const noPkgPostRes = await productsPostsPost({ request: makeReq('http://localhost/api/products-posts', 'POST', 'sess_inactive', { id: 'post_6' }), env });
  assert.equal(noPkgPostRes.status, 403);

  const expiredPostRes = await productsPostsPost({ request: makeReq('http://localhost/api/products-posts', 'POST', 'sess_trial', { id: 'post_6' }), env });
  const expiredPostData = await expiredPostRes.json();
  assert.equal(expiredPostRes.status, 403);
  assert.equal(expiredPostData.details?.trialExpired, true);

  const paidPostRes = await productsPostsPost({ request: makeReq('http://localhost/api/products-posts', 'POST', 'sess_paid', { id: 'post_6' }), env });
  assert.equal(paidPostRes.status, 200);
});

