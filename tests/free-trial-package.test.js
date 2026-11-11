import test from 'node:test';
import assert from 'node:assert/strict';
import { DatabaseSync } from 'node:sqlite';
import fs from 'node:fs';

import { onRequestGet as packagesGet, onRequestPost as packagesPost } from '../functions/api/packages.js';
import { onRequestPut as adminPackagesPut } from '../functions/api/admin/packages.js';
import { onRequestPost as adminPaymentsPost } from '../functions/api/admin/payments.js';
import { onRequestGet as authMeGet } from '../functions/api/auth/me.js';
import { onRequestGet as tasksGet, onRequestPost as tasksPost } from '../functions/api/tasks.js';
import { onRequestGet as surveysGet, onRequestPost as surveysPost } from '../functions/api/surveys.js';
import { onRequestPost as productsPostsPost } from '../functions/api/products-posts.js';
import { onRequestPost as withdrawalsPost } from '../functions/api/withdrawals.js';

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

function setupTestEnv() {
  const sqliteDb = new DatabaseSync(':memory:');
  const migrations = [
    'migrations/0001_initial_schema.sql',
    'migrations/0002_admin_products_and_verification.sql',
    'migrations/0005_referral_system.sql',
    'migrations/0006_package_withdrawal_limits_and_referral_balance.sql',
    'migrations/0007_submission_tickets.sql',
    'migrations/0008_paid_surveys.sql',
    'migrations/0009_active_user_bonus_system.sql',
    'migrations/0010_free_1day_trial_package.sql'
  ];

  for (const file of migrations) {
    if (fs.existsSync(file)) {
      const sql = fs.readFileSync(file, 'utf8');
      try {
        sqliteDb.exec(sql);
      } catch (_) {
        // Execute statement by statement for migrations with optional alters
        for (const stmt of sql.split(/;\s*\r?\n/)) {
          const clean = stmt.trim();
          if (clean) {
            try { sqliteDb.exec(clean); } catch (_) {}
          }
        }
      }
    }
  }

  // Ensure users/wallets/task_submissions columns used across handlers exist cleanly
  const extraAlters = [
    'ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE task_submissions ADD COLUMN evidence_id TEXT',
    "ALTER TABLE withdrawal_requests ADD COLUMN payment_method TEXT DEFAULT 'mpesa'"
  ];
  for (const stmt of extraAlters) {
    try { sqliteDb.exec(stmt); } catch (_) {}
  }

  // Seed paid packages matching production values
  sqliteDb.exec(`
    INSERT OR REPLACE INTO packages (id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, min_withdrawal_views_ksh, features, badge, is_active, created_at, duration_hours, is_free_trial)
    VALUES
      ('pkg_starter', 'Starter Pro', 'starter', 250, 20, 50, 5000, '["Starter feature"]', 'Entry Tier', 1, unixepoch(), NULL, 0),
      ('pkg_exclusive', 'Exclusive', 'exclusive', 500, 50, 100, 8000, '["Exclusive feature"]', 'Most Popular', 1, unixepoch(), NULL, 0),
      ('pkg_premium', 'Premium', 'premium', 1200, 100, 200, 12000, '["Premium feature"]', 'Maximum Earnings', 1, unixepoch(), NULL, 0);
  `);

  const now = Math.floor(Date.now() / 1000);
  sqliteDb.exec(`
    INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, referral_code, created_at, updated_at)
    VALUES
      ('usr_admin', 'Admin Mentor', '0700000001', 'mentorbravin@gmail.com', 'h', 's', 'admin', 'active', 'ADMIN1', ${now}, ${now}),
      ('usr_trial', 'Trial User', '0711111111', 'trial@example.com', 'h', 's', 'user', 'active', 'TRIAL1', ${now}, ${now}),
      ('usr_paid', 'Paid User', '0722222222', 'paid@example.com', 'h', 's', 'user', 'active', 'PAID01', ${now}, ${now});

    INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
    VALUES
      ('wal_trial', 'usr_trial', 0, 0, 0, 0, 0, 0, 0, ${now}),
      ('wal_paid', 'usr_paid', 2000, 2000, 0, 0, 0, 2000, 0, ${now});

    INSERT INTO user_packages (id, user_id, package_id, status, activated_at, expires_at)
    VALUES ('upkg_paid', 'usr_paid', 'pkg_premium', 'active', ${now - 864000}, NULL);

    INSERT INTO sessions (id, user_id, expires_at, created_at)
    VALUES
      ('sess_admin', 'usr_admin', ${now + 86400}, ${now}),
      ('sess_trial', 'usr_trial', ${now + 86400}, ${now}),
      ('sess_paid', 'usr_paid', ${now + 86400}, ${now});

    INSERT INTO campaigns (id, title, brand_name, description, target_link, guidelines, status, created_at)
    VALUES ('cmp_1', 'Test Brand Push', 'Almai Brand', 'Share on status', 'https://almai.co.ke', 'Post for 18h', 'active', ${now});

    INSERT INTO product_posts (id, title, brand_name, description, caption, image_url, image_base64, status, downloads_count, created_at)
    VALUES ('post_1', 'Promo Creative', 'Almai', 'Promo desc', 'Buy today', 'https://example.com/a.jpg', 'data:image/png;base64,iVBORw0KGgo=', 'active', 0, ${now});
  `);

  return {
    sqliteDb,
    env: { DB: createD1Wrapper(sqliteDb) }
  };
}

function makeReq(url, method = 'GET', sessionToken = null, body = null) {
  const headers = { 'Content-Type': 'application/json' };
  if (sessionToken) headers.Authorization = `Bearer ${sessionToken}`;
  return new Request(url, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });
}

test('Free 1-day trial package lifecycle, expiry lockout, upgrade flow, and paid plan non-interference', async () => {
  const { sqliteDb, env } = setupTestEnv();

  // 1. Public GET /api/packages returns 1-Day Free Trial + untouched paid plans
  const pkgListRes = await packagesGet({ env });
  const pkgList = await pkgListRes.json();
  assert.equal(pkgListRes.status, 200);
  assert.equal(pkgList.success, true);

  const byId = Object.fromEntries(pkgList.packages.map(p => [p.id, p]));
  assert.ok(byId.pkg_free_trial, 'pkg_free_trial should be returned');
  assert.equal(byId.pkg_free_trial.price_ksh, 0);
  assert.equal(byId.pkg_free_trial.duration_hours, 24);
  assert.equal(byId.pkg_free_trial.is_free_trial, 1);

  assert.equal(byId.pkg_starter.price_ksh, 250);
  assert.equal(byId.pkg_starter.duration_hours, null);
  assert.equal(byId.pkg_exclusive.price_ksh, 500);
  assert.equal(byId.pkg_exclusive.duration_hours, null);
  assert.equal(byId.pkg_premium.price_ksh, 1200);
  assert.equal(byId.pkg_premium.duration_hours, null);

  // 2. Paid user on Premium cannot accidentally activate free trial and stays permanently active
  const paidMeBeforeRes = await authMeGet({ request: makeReq('http://localhost/api/auth/me', 'GET', 'sess_paid'), env });
  const paidMeBefore = await paidMeBeforeRes.json();
  assert.equal(paidMeBefore.hasActivePackage, true);
  assert.equal(paidMeBefore.isTrialActive, false);
  assert.equal(paidMeBefore.isTrialExpiredLockout, false);
  assert.equal(paidMeBefore.activePackage.package_id, 'pkg_premium');

  const paidClaimFreeRes = await packagesPost({
    request: makeReq('http://localhost/api/packages', 'POST', 'sess_paid', { packageId: 'pkg_free_trial' }),
    env
  });
  assert.equal(paidClaimFreeRes.status, 409);

  // 3. New user activates 1-Day Free Trial instantly without M-Pesa code
  const activateTrialRes = await packagesPost({
    request: makeReq('http://localhost/api/packages', 'POST', 'sess_trial', { packageId: 'pkg_free_trial' }),
    env
  });
  const activateTrialData = await activateTrialRes.json();
  assert.equal(activateTrialRes.status, 200);
  assert.equal(activateTrialData.activated, true);
  assert.equal(activateTrialData.isTrial, true);
  assert.equal(activateTrialData.durationHours, 24);

  // Check active trial state via /api/auth/me
  const trialMeRes = await authMeGet({ request: makeReq('http://localhost/api/auth/me', 'GET', 'sess_trial'), env });
  const trialMe = await trialMeRes.json();
  assert.equal(trialMe.hasActivePackage, true);
  assert.equal(trialMe.isTrialActive, true);
  assert.equal(trialMe.isTrialExpiredLockout, false);
  assert.ok(trialMe.trialSecondsRemaining > 86000 && trialMe.trialSecondsRemaining <= 86400);

  // 4. During active 1-day trial, company services are unlocked (tasks + surveys)
  const taskResDay1 = await tasksPost({
    request: makeReq('http://localhost/api/tasks', 'POST', 'sess_trial', {
      campaignId: 'cmp_1',
      reportedViews: 10,
      evidenceBase64: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
      evidenceNote: 'Posted on status during trial'
    }),
    env
  });
  assert.equal(taskResDay1.status, 201, 'Task submission should succeed during active 1-day trial');

  // Cannot claim free trial twice
  const doubleClaimRes = await packagesPost({
    request: makeReq('http://localhost/api/packages', 'POST', 'sess_trial', { packageId: 'pkg_free_trial' }),
    env
  });
  assert.equal(doubleClaimRes.status, 409);

  // 5. Simulate 25 hours passing so 1-Day Free Trial expires
  const pastStart = Math.floor(Date.now() / 1000) - (25 * 3600);
  const pastExpiry = pastStart + (24 * 3600); // expired 1 hour ago
  sqliteDb.prepare(`
    UPDATE user_packages
    SET activated_at = ?, expires_at = ?
    WHERE user_id = 'usr_trial' AND package_id = 'pkg_free_trial'
  `).run(pastStart, pastExpiry);

  // Clear cooldown restriction so /api/tasks test specifically tests trial expiry lockout
  sqliteDb.prepare(`DELETE FROM task_submissions WHERE user_id = 'usr_trial'`).run();

  // Check /api/auth/me auto-expires trial and flags lockout
  const expiredMeRes = await authMeGet({ request: makeReq('http://localhost/api/auth/me', 'GET', 'sess_trial'), env });
  const expiredMe = await expiredMeRes.json();
  assert.equal(expiredMe.hasActivePackage, false);
  assert.equal(expiredMe.isTrialActive, false);
  assert.equal(expiredMe.isTrialExpiredLockout, true);
  assert.equal(expiredMe.hasUsedFreeTrial, true);

  // Also load seeded surveys once via GET /api/surveys before checking survey POST lockout
  const srvListRes = await surveysGet({ request: makeReq('http://localhost/api/surveys', 'GET', 'sess_trial'), env });
  const srvListData = await srvListRes.json();
  assert.equal(srvListRes.status, 200);
  assert.equal(srvListData.isTrialExpiredLockout, true);
  const firstSurvey = srvListData.surveys[0];
  const validAnswers = Object.fromEntries(firstSurvey.questions.map(q => [q.id, q.options[0]]));

  // Expired user MUST be locked out of Tasks, Surveys, Product Downloads, and Withdrawals
  const lockedTaskRes = await tasksPost({
    request: makeReq('http://localhost/api/tasks', 'POST', 'sess_trial', {
      campaignId: 'cmp_1',
      reportedViews: 10,
      evidenceNote: 'Should be blocked'
    }),
    env
  });
  const lockedTaskData = await lockedTaskRes.json();
  assert.equal(lockedTaskRes.status, 403);
  assert.equal(lockedTaskData.details?.trialExpired, true);

  const lockedSurveyRes = await surveysPost({
    request: makeReq('http://localhost/api/surveys', 'POST', 'sess_trial', {
      surveyId: firstSurvey.id,
      answers: validAnswers
    }),
    env
  });
  const lockedSurveyData = await lockedSurveyRes.json();
  assert.equal(lockedSurveyRes.status, 403);
  assert.equal(lockedSurveyData.details?.trialExpired, true);

  const lockedDownloadRes = await productsPostsPost({
    request: makeReq('http://localhost/api/products-posts', 'POST', 'sess_trial', { id: 'post_1' }),
    env
  });
  const lockedDownloadData = await lockedDownloadRes.json();
  assert.equal(lockedDownloadRes.status, 403);
  assert.equal(lockedDownloadData.details?.trialExpired, true);

  // Give trial user balance so withdrawal test explicitly proves trial-lockout 403 (not 404/balance error)
  sqliteDb.prepare(`UPDATE wallets SET available_balance_ksh = 6000, views_balance_ksh = 6000 WHERE user_id = 'usr_trial'`).run();
  const lockedWithdrawRes = await withdrawalsPost({
    request: makeReq('http://localhost/api/withdrawals', 'POST', 'sess_trial', {
      amountKsh: 5000,
      phoneNumber: '0711111111',
      balanceType: 'views'
    }),
    env
  });
  const lockedWithdrawData = await lockedWithdrawRes.json();
  assert.equal(lockedWithdrawRes.status, 403);
  assert.equal(lockedWithdrawData.details?.trialExpired, true);

  // GET /api/tasks also exposes packageState.isTrialExpiredLockout
  const tasksGetRes = await tasksGet({ request: makeReq('http://localhost/api/tasks', 'GET', 'sess_trial'), env });
  const tasksGetData = await tasksGetRes.json();
  assert.equal(tasksGetRes.status, 200);
  assert.equal(tasksGetData.packageState?.isTrialExpiredLockout, true);

  // 6. Flexible Admin package configuration works for free trial without altering paid plans
  const adminPutRes = await adminPackagesPut({
    request: makeReq('http://localhost/api/admin/packages', 'PUT', 'sess_admin', {
      id: 'pkg_free_trial',
      durationHours: 48,
      rewardPerViewKsh: 18
    }),
    env
  });
  const adminPutData = await adminPutRes.json();
  assert.equal(adminPutRes.status, 200);
  assert.equal(adminPutData.package.duration_hours, 48);
  assert.equal(adminPutData.package.reward_per_view_ksh, 18);

  // Paid plan still untouched
  const starterRow = sqliteDb.prepare("SELECT price_ksh, duration_hours, is_free_trial FROM packages WHERE id = 'pkg_starter'").get();
  assert.equal(starterRow.price_ksh, 250);
  assert.equal(starterRow.duration_hours, null);
  assert.equal(starterRow.is_free_trial, 0);

  // 7. Upgrade from expired Free Trial -> Starter Pro unlocks company services permanently
  const submitUpgradeRes = await packagesPost({
    request: makeReq('http://localhost/api/packages', 'POST', 'sess_trial', {
      packageId: 'pkg_starter',
      paymentReference: 'MPESAUPGRADE99',
      phoneNumber: '0711111111'
    }),
    env
  });
  assert.ok(submitUpgradeRes.status === 200 || submitUpgradeRes.status === 201);

  const pendingPayment = sqliteDb.prepare(`SELECT id FROM payment_transactions WHERE user_id = 'usr_trial' AND status = 'pending'`).get();
  assert.ok(pendingPayment);

  const verifyRes = await adminPaymentsPost({
    request: makeReq('http://localhost/api/admin/payments', 'POST', 'sess_admin', {
      paymentId: pendingPayment.id,
      action: 'verify'
    }),
    env
  });
  assert.equal(verifyRes.status, 200);

  const upgradedMeRes = await authMeGet({ request: makeReq('http://localhost/api/auth/me', 'GET', 'sess_trial'), env });
  const upgradedMe = await upgradedMeRes.json();
  assert.equal(upgradedMe.hasActivePackage, true);
  assert.equal(upgradedMe.isTrialActive, false);
  assert.equal(upgradedMe.isTrialExpiredLockout, false);
  assert.equal(upgradedMe.activePackage.package_id, 'pkg_starter');
  assert.equal(upgradedMe.activePackage.expires_at, null);

  // Unlocked survey & task work immediately after upgrade!
  const unlockedSurveyRes = await surveysPost({
    request: makeReq('http://localhost/api/surveys', 'POST', 'sess_trial', {
      surveyId: firstSurvey.id,
      answers: validAnswers
    }),
    env
  });
  assert.equal(unlockedSurveyRes.status, 200, 'Surveys should unlock after paid package upgrade');

  const unlockedTaskRes = await tasksPost({
    request: makeReq('http://localhost/api/tasks', 'POST', 'sess_trial', {
      campaignId: 'cmp_1',
      reportedViews: 20,
      evidenceBase64: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
      evidenceNote: 'Upgraded starter proof'
    }),
    env
  });
  assert.equal(unlockedTaskRes.status, 201, 'Tasks should unlock after paid package upgrade');

  // Existing Premium user still unaffected
  const paidMeAfterRes = await authMeGet({ request: makeReq('http://localhost/api/auth/me', 'GET', 'sess_paid'), env });
  const paidMeAfter = await paidMeAfterRes.json();
  assert.equal(paidMeAfter.hasActivePackage, true);
  assert.equal(paidMeAfter.activePackage.package_id, 'pkg_premium');
  assert.equal(paidMeAfter.activePackage.expires_at, null);
});
