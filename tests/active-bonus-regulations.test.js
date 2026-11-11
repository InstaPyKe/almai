import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';
import { onRequestGet as bonusesGet, onRequestPost as bonusesPost } from '../functions/api/admin/bonuses.js';
import { onRequestGet as statsGet } from '../functions/api/admin/stats.js';

function createD1Wrapper(sqliteDb) {
  return {
    prepare(sql) {
      const runWithArgs = (args = []) => {
        const stmt = sqliteDb.prepare(sql);
        return { stmt, args };
      };
      return {
        bind(...args) {
          return {
            async first() {
              const { stmt } = runWithArgs(args);
              return stmt.get(...args) ?? null;
            },
            async all() {
              const { stmt } = runWithArgs(args);
              return { results: stmt.all(...args) };
            },
            async run() {
              const { stmt } = runWithArgs(args);
              const info = stmt.run(...args);
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

function setupTestEnv() {
  const sqliteDb = new DatabaseSync(':memory:');
  const baseSql = fs.readFileSync('migrations/0001_initial_schema.sql', 'utf8');
  sqliteDb.exec(baseSql);
  sqliteDb.exec('ALTER TABLE packages ADD COLUMN min_withdrawal_views_ksh INTEGER NOT NULL DEFAULT 5000;');
  sqliteDb.exec('ALTER TABLE users ADD COLUMN referral_code TEXT;');
  sqliteDb.exec('ALTER TABLE wallets ADD COLUMN views_balance_ksh INTEGER NOT NULL DEFAULT 0;');
  sqliteDb.exec('ALTER TABLE wallets ADD COLUMN referrals_balance_ksh INTEGER NOT NULL DEFAULT 0;');
  sqliteDb.exec('ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0;');
  sqliteDb.exec('CREATE TABLE IF NOT EXISTS product_posts (id TEXT PRIMARY KEY, status TEXT DEFAULT \'active\');');
  sqliteDb.exec('CREATE TABLE IF NOT EXISTS surveys (id TEXT PRIMARY KEY, is_active INTEGER DEFAULT 1);');
  sqliteDb.exec('CREATE TABLE IF NOT EXISTS survey_responses (id TEXT PRIMARY KEY, reward_amount_ksh INTEGER DEFAULT 0);');
  sqliteDb.exec(fs.readFileSync('migrations/0009_active_user_bonus_system.sql', 'utf8'));

  const now = Math.floor(Date.now() / 1000);

  // Seed admin user & session
  sqliteDb.prepare(`
    INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, created_at, updated_at)
    VALUES ('usr_admin', 'Super Admin', '0700000000', 'mentorbravin@gmail.com', 'h', 's', 'admin', 'active', ?, ?)
  `).run(now, now);
  sqliteDb.prepare(`
    INSERT INTO sessions (id, user_id, expires_at, created_at)
    VALUES ('tok_admin', 'usr_admin', ?, ?)
  `).run(now + 3600, now);

  // Seed packages
  sqliteDb.prepare(`
    INSERT OR IGNORE INTO packages (id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, min_withdrawal_views_ksh, features, badge, is_active, created_at)
    VALUES
      ('pkg_starter', 'Starter Pro', 'starter', 250, 20, 50, 5000, '[]', 'Starter', 1, ?),
      ('pkg_premium', 'Premium', 'premium', 1200, 100, 200, 12000, '[]', 'Premium', 1, ?)
  `).run(now, now);

  // Seed 3 partners:
  // 1) Active paid user (Premium)
  sqliteDb.prepare(`
    INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, created_at, updated_at)
    VALUES ('usr_paid_1', 'Active Paid Partner', '0711111111', 'paid1@almai.test', 'h', 's', 'user', 'active', ?, ?)
  `).run(now, now);
  sqliteDb.prepare(`
    INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
    VALUES ('wal_paid_1', 'usr_paid_1', 500, 500, 0, 0, 0, 500, 0, ?)
  `).run(now);
  sqliteDb.prepare(`
    INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
    VALUES ('up_1', 'usr_paid_1', 'pkg_premium', 'active', ?)
  `).run(now);

  // 2) Active unpaid user (no active package)
  sqliteDb.prepare(`
    INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, created_at, updated_at)
    VALUES ('usr_free_1', 'Active Free User', '0722222222', 'free1@almai.test', 'h', 's', 'user', 'active', ?, ?)
  `).run(now, now);
  sqliteDb.prepare(`
    INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
    VALUES ('wal_free_1', 'usr_free_1', 0, 0, 0, 0, 0, 0, 0, ?)
  `).run(now);

  // 3) Suspended user with active package (must NEVER receive active bonus)
  sqliteDb.prepare(`
    INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, created_at, updated_at)
    VALUES ('usr_susp_1', 'Suspended User', '0733333333', 'susp1@almai.test', 'h', 's', 'user', 'suspended', ?, ?)
  `).run(now, now);
  sqliteDb.prepare(`
    INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
    VALUES ('up_susp', 'usr_susp_1', 'pkg_starter', 'active', ?)
  `).run(now);
  sqliteDb.prepare(`
    INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
    VALUES ('wal_susp_1', 'usr_susp_1', 100, 100, 0, 0, 0, 100, 0, ?)
  `).run(now);

  const env = { DB: createD1Wrapper(sqliteDb) };
  return { sqliteDb, env };
}

function makeReq(url, method = 'GET', body = null, token = 'tok_admin') {
  return new Request(url, {
    method,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {})
    },
    ...(body ? { body: JSON.stringify(body) } : {})
  });
}

test('Admin regulated active user bonus policy & payout enforcement', async () => {
  const { sqliteDb, env } = setupTestEnv();

  // 1. Initial GET policy & active user summary
  const resGet1 = await bonusesGet({ request: makeReq('https://almai.test/api/admin/bonuses'), env });
  assert.equal(resGet1.status, 200);
  const get1 = await resGet1.json();
  assert.equal(get1.success, true);
  assert.equal(get1.activeSummary.activePaidCount, 1);
  assert.equal(get1.activeSummary.activeRegisteredCount, 2); // usr_paid_1 + usr_free_1 (excludes admin & suspended)

  // 2. Save strict admin regulations: min=100, max=600, dailyCap=1000, cooldown=24h, requireActivePackage=1
  const resSave = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'save_regulations',
      isEnabled: 1,
      minBonusKsh: 100,
      maxBonusPerUserKsh: 600,
      dailyBudgetCapKsh: 1000,
      cooldownHours: 24,
      requireActivePackage: 1,
      defaultBalanceType: 'views'
    }),
    env
  });
  assert.equal(resSave.status, 200);

  // 3. Reject amount above max_bonus_per_user_ksh (800 > 600)
  const resOverMax = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'Too Large Bonus',
      amountPerUserKsh: 800,
      scope: 'active_paid'
    }),
    env
  });
  assert.equal(resOverMax.status, 400);
  const overMaxJson = await resOverMax.json();
  assert.match(overMaxJson.error, /violates admin regulation range/i);

  // 4. Reject targeting all_active when requireActivePackage=1
  const resRequirePkg = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'Free User Block Test',
      amountPerUserKsh: 250,
      scope: 'all_active'
    }),
    env
  });
  assert.equal(resRequirePkg.status, 400);
  const reqPkgJson = await resRequirePkg.json();
  assert.match(reqPkgJson.error, /requires an Active Paid Package/i);

  // 5. Distribute valid bonus KSh 400 to active paid partners
  const resDist = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'Loyalty Bonus #1',
      amountPerUserKsh: 400,
      scope: 'active_paid',
      balanceType: 'views'
    }),
    env
  });
  assert.equal(resDist.status, 200);
  const distJson = await resDist.json();
  assert.equal(distJson.distribution.recipientCount, 1);
  assert.equal(distJson.distribution.totalDisbursedKsh, 400);

  // Check wallet credited properly (only usr_paid_1, NOT usr_free_1 or usr_susp_1)
  const paidWal = sqliteDb.prepare("SELECT * FROM wallets WHERE user_id = 'usr_paid_1'").get();
  const freeWal = sqliteDb.prepare("SELECT * FROM wallets WHERE user_id = 'usr_free_1'").get();
  const suspWal = sqliteDb.prepare("SELECT * FROM wallets WHERE user_id = 'usr_susp_1'").get();
  assert.equal(paidWal.views_balance_ksh, 900);
  assert.equal(paidWal.available_balance_ksh, 900);
  assert.equal(paidWal.lifetime_earnings_ksh, 900);
  assert.equal(freeWal.available_balance_ksh, 0);
  assert.equal(suspWal.available_balance_ksh, 100);

  // Check wallet_transactions logged with valid 'adjustment' type
  const txRow = sqliteDb.prepare("SELECT * FROM wallet_transactions WHERE user_id = 'usr_paid_1'").get();
  assert.equal(txRow.type, 'adjustment');
  assert.equal(txRow.amount_ksh, 400);

  // 6. Enforce cooldown regulation: immediate re-reward must skip usr_paid_1
  const resCooldown = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'Duplicate Try',
      amountPerUserKsh: 300,
      scope: 'active_paid'
    }),
    env
  });
  assert.equal(resCooldown.status, 400);
  const cooldownJson = await resCooldown.json();
  assert.match(cooldownJson.error, /cooldown regulation/i);

  // 7. Disable cooldown + allow all_active users + check 24h daily budget cap (remaining = 600)
  await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'save_regulations',
      isEnabled: 1,
      minBonusKsh: 100,
      maxBonusPerUserKsh: 600,
      dailyBudgetCapKsh: 1000,
      cooldownHours: 0,
      requireActivePackage: 0,
      defaultBalanceType: 'surveys'
    }),
    env
  });

  // Trying KSh 400 x 2 active users = 800 > 600 remaining -> blocked by daily budget cap!
  const resOverBudget = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'Over Cap Test',
      amountPerUserKsh: 400,
      scope: 'all_active'
    }),
    env
  });
  assert.equal(resOverBudget.status, 400);
  const overBudgetJson = await resOverBudget.json();
  assert.match(overBudgetJson.error, /exceeds remaining regulated 24h budget cap/i);

  // KSh 300 x 2 active users = 600 <= 600 remaining -> succeeds into surveys ledger!
  const resAllActive = await bonusesPost({
    request: makeReq('https://almai.test/api/admin/bonuses', 'POST', {
      action: 'distribute',
      campaignTitle: 'All Active Bonus',
      amountPerUserKsh: 300,
      scope: 'all_active',
      balanceType: 'surveys'
    }),
    env
  });
  assert.equal(resAllActive.status, 200);
  const allActiveJson = await resAllActive.json();
  assert.equal(allActiveJson.distribution.recipientCount, 2);
  assert.equal(allActiveJson.distribution.totalDisbursedKsh, 600);
  assert.equal(allActiveJson.budgetStats.remainingDailyBudgetKsh, 0);

  // Check admin stats reflects totalBonusDisbursedKsh = 1000
  const statsRes = await statsGet({ request: makeReq('https://almai.test/api/admin/stats'), env });
  const statsJson = await statsRes.json();
  assert.equal(statsJson.metrics.totalBonusDisbursedKsh, 1000);
  assert.equal(statsJson.metrics.totalBonusRecipientsCount, 3);
});
