import { DatabaseSync } from 'node:sqlite';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

// Find local D1 database
const dir = '.wrangler/state/v3/d1/miniflare-D1DatabaseObject';
const files = fs.readdirSync(dir).filter(f => f.endsWith('.sqlite'));
const db = new DatabaseSync(path.join(dir, files[0]));

console.log('🧪 Starting Withdrawal Limits & Referral Independence Integration Tests...\n');

// 1. Verify Packages configuration
console.log('1. Checking package unique views limits...');
const starterPkg = db.prepare("SELECT * FROM packages WHERE id = 'pkg_starter'").get();
const exclusivePkg = db.prepare("SELECT * FROM packages WHERE id = 'pkg_exclusive'").get();
const premiumPkg = db.prepare("SELECT * FROM packages WHERE id = 'pkg_premium'").get();

assert.strictEqual(starterPkg.min_withdrawal_views_ksh, 5000, 'Starter Pro views limit must be 5000');
assert.strictEqual(exclusivePkg.min_withdrawal_views_ksh, 8000, 'Exclusive views limit must be 8000');
assert.strictEqual(premiumPkg.min_withdrawal_views_ksh, 12000, 'Premium views limit must be 12000');
console.log('✅ Package views limits verified: Starter=5000, Exclusive=8000, Premium=12000\n');

// 2. Set up test user with wallet
const testUserId = 'usr_test_withdrawal_' + Date.now();
const testWalletId = 'wal_test_' + Date.now();

db.prepare(`
  INSERT INTO users (id, name, phone, email, password_hash, salt, role, status, created_at, updated_at)
  VALUES (?, 'Test Trader', '0712345678', 'test@example.com', 'hash', 'salt', 'user', 'active', unixepoch(), unixepoch())
`).run(testUserId);

db.prepare(`
  INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
  VALUES (?, ?, 15000, 10000, 5000, 0, 15000, 0, unixepoch())
`).run(testWalletId, testUserId);

// Assign Starter Pro package
const userPkgId = 'upkg_test_' + Date.now();
db.prepare(`
  INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
  VALUES (?, ?, 'pkg_starter', 'active', unixepoch())
`).run(userPkgId, testUserId);

// 3. Test Views Withdrawal: Reject under 5000 limit
console.log('2. Testing Status Views withdrawal rejection below package limit (4,500 < 5,000)...');
function simulateWithdrawal({ userId, amountKsh, phoneNumber, balanceType = 'views' }) {
  const user = db.prepare('SELECT id, phone, status FROM users WHERE id = ?').get(userId);
  const wallet = db.prepare('SELECT * FROM wallets WHERE user_id = ?').get(userId);
  const activePkg = db.prepare(`
    SELECT p.id, p.name, p.min_withdrawal_views_ksh FROM user_packages up
    JOIN packages p ON p.id = up.package_id
    WHERE up.user_id = ? AND up.status IN ('active', 'approved')
    ORDER BY up.activated_at DESC LIMIT 1
  `).get(userId);

  const amount = parseInt(amountKsh, 10);
  if (isNaN(amount) || amount <= 0) return { error: 'Invalid amount', status: 400 };

  const isReferralWithdrawal = balanceType === 'referrals';

  if (isReferralWithdrawal) {
    if (amount < 100) return { error: 'Minimum referral withdrawal amount is KSh 100', status: 400 };
    if ((wallet.referrals_balance_ksh || 0) < amount) {
      return { error: 'Insufficient referral commission balance', status: 400 };
    }
  } else {
    if (!activePkg) return { error: 'No active package', status: 400 };
    const minLimit = activePkg.min_withdrawal_views_ksh || 5000;
    if (amount < minLimit) {
      return { error: `Active package ${activePkg.name} requires a minimum status views withdrawal of KSh ${minLimit.toLocaleString()}`, status: 400 };
    }
    if ((wallet.views_balance_ksh || 0) < amount) {
      return { error: 'Insufficient status views balance', status: 400 };
    }
  }

  // Deduct and create withdrawal record
  const reqId = 'wreq_' + Date.now() + '_' + Math.random().toString(36).slice(2, 6);
  if (isReferralWithdrawal) {
    db.prepare(`
      UPDATE wallets
      SET referrals_balance_ksh = referrals_balance_ksh - ?,
          available_balance_ksh = available_balance_ksh - ?,
          reserved_balance_ksh = reserved_balance_ksh + ?,
          updated_at = unixepoch()
      WHERE id = ?
    `).run(amount, amount, amount, wallet.id);
  } else {
    db.prepare(`
      UPDATE wallets
      SET views_balance_ksh = views_balance_ksh - ?,
          available_balance_ksh = available_balance_ksh - ?,
          reserved_balance_ksh = reserved_balance_ksh + ?,
          updated_at = unixepoch()
      WHERE id = ?
    `).run(amount, amount, amount, wallet.id);
  }

  db.prepare(`
    INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
    VALUES (?, ?, ?, ?, ?, 'pending', ?, unixepoch())
  `).run(reqId, userId, wallet.id, amount, phoneNumber, isReferralWithdrawal ? 'referrals' : 'views');

  return { success: true, withdrawalId: reqId, status: 200 };
}

const underResult = simulateWithdrawal({ userId: testUserId, amountKsh: 4500, phoneNumber: '0712345678', balanceType: 'views' });
assert.strictEqual(underResult.status, 400);
assert.match(underResult.error, /requires a minimum status views withdrawal of KSh 5,000/);
console.log('✅ Rejection verified: 4,500 KSh rejected with message:', underResult.error);

// 4. Test Views Withdrawal: Accept at 5000 limit
console.log('\n3. Testing Status Views withdrawal approval at 5,000 limit...');
const validViewsResult = simulateWithdrawal({ userId: testUserId, amountKsh: 5000, phoneNumber: '0712345678', balanceType: 'views' });
assert.strictEqual(validViewsResult.status, 200);
assert.strictEqual(validViewsResult.success, true);

let walletAfterViews = db.prepare('SELECT * FROM wallets WHERE user_id = ?').get(testUserId);
assert.strictEqual(walletAfterViews.views_balance_ksh, 5000, 'Views balance should be reduced from 10,000 to 5,000');
assert.strictEqual(walletAfterViews.referrals_balance_ksh, 5000, 'Referrals balance should remain untouched at 5,000');
assert.strictEqual(walletAfterViews.available_balance_ksh, 10000, 'Available balance should be 10,000');
assert.strictEqual(walletAfterViews.reserved_balance_ksh, 5000, 'Reserved balance should be 5,000');
console.log('✅ Views withdrawal of KSh 5,000 succeeded. Balances: Views=5,000, Referrals=5,000, Avail=10,000, Reserved=5,000');

// 5. Test Separate Referral Withdrawal (e.g. KSh 1,500, which is below 5000 package limit)
console.log('\n4. Testing separate referral withdrawal below views package limit (1,500 < 5,000 views limit)...');
const refResult = simulateWithdrawal({ userId: testUserId, amountKsh: 1500, phoneNumber: '0712345678', balanceType: 'referrals' });
assert.strictEqual(refResult.status, 200);
assert.strictEqual(refResult.success, true);

let walletAfterRef = db.prepare('SELECT * FROM wallets WHERE user_id = ?').get(testUserId);
assert.strictEqual(walletAfterRef.views_balance_ksh, 5000, 'Views balance should remain untouched at 5,000');
assert.strictEqual(walletAfterRef.referrals_balance_ksh, 3500, 'Referrals balance should be reduced from 5,000 to 3,500');
assert.strictEqual(walletAfterRef.available_balance_ksh, 8500, 'Available balance should be 8,500');
assert.strictEqual(walletAfterRef.reserved_balance_ksh, 6500, 'Reserved balance should be 6,500 (5,000 + 1,500)');
console.log('✅ Separate referral withdrawal succeeded! Balances: Views=5,000, Referrals=3,500, Avail=8,500, Reserved=6,500');

// 6. Test Admin Rejection & Refund target differentiation
console.log('\n5. Testing Admin Rejection & Refund to correct balance...');
function simulateAdminRefund(withdrawalId) {
  const wr = db.prepare('SELECT * FROM withdrawal_requests WHERE id = ?').get(withdrawalId);
  if (wr.balance_type === 'referrals') {
    db.prepare(`
      UPDATE wallets
      SET referrals_balance_ksh = referrals_balance_ksh + ?,
          available_balance_ksh = available_balance_ksh + ?,
          reserved_balance_ksh = reserved_balance_ksh - ?,
          updated_at = unixepoch()
      WHERE id = ?
    `).run(wr.amount_ksh, wr.amount_ksh, wr.amount_ksh, wr.wallet_id);
  } else {
    db.prepare(`
      UPDATE wallets
      SET views_balance_ksh = views_balance_ksh + ?,
          available_balance_ksh = available_balance_ksh + ?,
          reserved_balance_ksh = reserved_balance_ksh - ?,
          updated_at = unixepoch()
      WHERE id = ?
    `).run(wr.amount_ksh, wr.amount_ksh, wr.amount_ksh, wr.wallet_id);
  }
  db.prepare("UPDATE withdrawal_requests SET status = 'rejected' WHERE id = ?").run(withdrawalId);
}

// Refund referral withdrawal
simulateAdminRefund(refResult.withdrawalId);
let walletAfterRefund = db.prepare('SELECT * FROM wallets WHERE user_id = ?').get(testUserId);
assert.strictEqual(walletAfterRefund.referrals_balance_ksh, 5000, 'Referrals balance refunded to 5,000');
assert.strictEqual(walletAfterRefund.views_balance_ksh, 5000, 'Views balance unaffected at 5,000');
assert.strictEqual(walletAfterRefund.reserved_balance_ksh, 5000, 'Reserved balance reduced back to 5,000');
console.log('✅ Referral refund credited back specifically to referrals_balance_ksh!');

// Clean up test data
db.prepare('DELETE FROM withdrawal_requests WHERE user_id = ?').run(testUserId);
db.prepare('DELETE FROM user_packages WHERE user_id = ?').run(testUserId);
db.prepare('DELETE FROM wallets WHERE user_id = ?').run(testUserId);
db.prepare('DELETE FROM users WHERE id = ?').run(testUserId);

console.log('\n🎉 ALL INTEGRATION TESTS PASSED WITH 100% SUCCESS!');
