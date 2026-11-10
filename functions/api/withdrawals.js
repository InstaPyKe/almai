// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/withdrawals
// Package Unique Views Limits & Separate Referral Payouts
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, generateId } from './_utils.js';

const MINIMUM_WITHDRAWAL_KSH = 100;

/**
 * GET /api/withdrawals
 * Get withdrawal history and current wallet balance with breakdown
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  try {
    // Ensure surveys_balance_ksh column exists
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

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

    const activePackage = await env.DB.prepare(`
      SELECT p.id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.min_withdrawal_views_ksh
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      WHERE up.user_id = ? AND up.status = 'active'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();

    const { results: requests } = await env.DB.prepare(`
      SELECT id, amount_ksh, phone_number, status, balance_type, mpesa_receipt_number, rejection_reason, created_at, processed_at
      FROM withdrawal_requests
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(user.id).all();

    const minViewsWithdrawal = activePackage?.min_withdrawal_views_ksh || 5000;

    return jsonSuccess({
      wallet: wallet || { available_balance_ksh: 0, views_balance_ksh: 0, referrals_balance_ksh: 0, surveys_balance_ksh: 0, reserved_balance_ksh: 0, lifetime_withdrawn_ksh: 0 },
      activePackage: activePackage || null,
      minViewsWithdrawalKsh: minViewsWithdrawal,
      minReferralsWithdrawalKsh: MINIMUM_WITHDRAWAL_KSH,
      minSurveysWithdrawalKsh: MINIMUM_WITHDRAWAL_KSH,
      withdrawals: requests || []
    });

  } catch (err) {
    console.error('Fetch withdrawals error:', err);
    return jsonError('Failed to fetch withdrawal requests', 500);
  }
}

/**
 * POST /api/withdrawals
 * Request a real M-Pesa payout from available wallet earnings
 * Supports balanceType: 'views' (enforces package limit) or 'referrals' (independent separate withdrawal)
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const { amountKsh, phoneNumber, balanceType: rawBalanceType } = body;
  let balanceType = 'views';
  if (rawBalanceType === 'referrals' || rawBalanceType === 'referral') {
    balanceType = 'referrals';
  } else if (rawBalanceType === 'surveys' || rawBalanceType === 'survey') {
    balanceType = 'surveys';
  }

  const amount = parseInt(amountKsh, 10);
  if (isNaN(amount) || amount <= 0) {
    return jsonError('Please enter a valid withdrawal amount', 400);
  }

  const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, '') : user.phone;
  if (!targetPhone || targetPhone.length < 9) {
    return jsonError('Valid M-Pesa phone number is required for payout', 400);
  }

  try {
    // Ensure column exists
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

    // 1. Fetch current wallet
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
      return jsonError('Wallet account not found', 404);
    }

    const now = Math.floor(Date.now() / 1000);
    const withdrawalId = generateId('wth');
    const txId = generateId('wtx');

    if (balanceType === 'views') {
      // Fetch user's active package to enforce unique withdrawal limit for views
      const activePackage = await env.DB.prepare(`
        SELECT p.id, p.name, p.min_withdrawal_views_ksh
        FROM user_packages up
        JOIN packages p ON up.package_id = p.id
        WHERE up.user_id = ? AND up.status = 'active'
        ORDER BY up.activated_at DESC
        LIMIT 1
      `).bind(user.id).first();

      if (!activePackage) {
        return jsonError('You must have an active partner package to withdraw status views earnings. If you have referral earnings, you can withdraw them separately.', 400);
      }

      const minViewsLimit = activePackage.min_withdrawal_views_ksh || 5000;
      if (amount < minViewsLimit) {
        return jsonError(`Minimum withdrawal amount for Status Views on your ${activePackage.name} package is KSh ${minViewsLimit.toLocaleString()} (requested KSh ${amount.toLocaleString()}). Note: Referral commissions can be withdrawn separately without this limit.`, 400);
      }

      const availableViews = typeof wallet.views_balance_ksh === 'number' ? wallet.views_balance_ksh : wallet.available_balance_ksh;
      if (availableViews < amount) {
        return jsonError(`Insufficient Status Views earnings. Your available Views balance is KSh ${availableViews.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }

      const balanceAfter = wallet.available_balance_ksh - amount;

      // Atomically reserve funds from views balance
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = views_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND views_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();

      if (!updateResult.success || (updateResult.meta && updateResult.meta.changes === 0)) {
        return jsonError('Concurrent balance update conflict or insufficient views funds. Please refresh and try again.', 409);
      }

      // Record withdrawal request with balance_type = 'views'
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'views', ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetPhone, now).run();

      // Ledger entry
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
        `M-Pesa withdrawal request from Status Views (${activePackage.name}) to ${targetPhone} placed on hold pending payout`,
        now
      ).run();

      return jsonSuccess({
        message: `Status Views withdrawal request for KSh ${amount.toLocaleString()} submitted successfully. Funds have been reserved pending M-Pesa disbursement.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetPhone,
          balanceType: 'views',
          status: 'pending',
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

    } else if (balanceType === 'surveys') {
      const minSurveyLimit = MINIMUM_WITHDRAWAL_KSH;
      if (amount < minSurveyLimit) {
        return jsonError(`Minimum withdrawal amount for Paid Surveys is KSh ${minSurveyLimit}`, 400);
      }

      const availableSurveys = Number(wallet.surveys_balance_ksh || 0);
      if (availableSurveys < amount) {
        return jsonError(`Insufficient Paid Surveys earnings. Your available Surveys balance is KSh ${availableSurveys.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }

      const balanceAfter = wallet.available_balance_ksh - amount;

      // Atomically reserve funds from surveys balance
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET surveys_balance_ksh = surveys_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND surveys_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();

      if (!updateResult.success || (updateResult.meta && updateResult.meta.changes === 0)) {
        return jsonError('Concurrent balance update conflict or insufficient survey funds. Please refresh and try again.', 409);
      }

      // Record withdrawal request with balance_type = 'surveys'
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'surveys', ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetPhone, now).run();

      // Ledger entry
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
        `M-Pesa withdrawal request from Paid Surveys to ${targetPhone} placed on hold pending payout`,
        now
      ).run();

      return jsonSuccess({
        message: `Paid Surveys withdrawal request for KSh ${amount.toLocaleString()} submitted successfully. Funds have been reserved pending M-Pesa disbursement.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetPhone,
          balanceType: 'surveys',
          status: 'pending',
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
      // balanceType === 'referrals'
      const minReferralLimit = MINIMUM_WITHDRAWAL_KSH;
      if (amount < minReferralLimit) {
        return jsonError(`Minimum withdrawal amount for Referral Commissions is KSh ${minReferralLimit}`, 400);
      }

      const availableReferrals = wallet.referrals_balance_ksh || 0;
      if (availableReferrals < amount) {
        return jsonError(`Insufficient Referral Commission funds. Your available Referral balance is KSh ${availableReferrals.toLocaleString()}, requested KSh ${amount.toLocaleString()}.`, 400);
      }

      const balanceAfter = wallet.available_balance_ksh - amount;

      // Atomically reserve funds from referrals balance
      const updateResult = await env.DB.prepare(`
        UPDATE wallets
        SET referrals_balance_ksh = referrals_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh - ?,
            reserved_balance_ksh = reserved_balance_ksh + ?,
            updated_at = ?
        WHERE user_id = ? AND referrals_balance_ksh >= ?
      `).bind(amount, amount, amount, now, user.id, amount).run();

      if (!updateResult.success || (updateResult.meta && updateResult.meta.changes === 0)) {
        return jsonError('Concurrent balance update conflict or insufficient referral funds. Please refresh and try again.', 409);
      }

      // Record withdrawal request with balance_type = 'referrals'
      await env.DB.prepare(`
        INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, balance_type, created_at)
        VALUES (?, ?, ?, ?, ?, 'pending', 'referrals', ?)
      `).bind(withdrawalId, user.id, wallet.id, amount, targetPhone, now).run();

      // Ledger entry
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
        `M-Pesa withdrawal request from Referral Commissions to ${targetPhone} placed on hold pending payout`,
        now
      ).run();

      return jsonSuccess({
        message: `Referral Commission withdrawal request for KSh ${amount.toLocaleString()} submitted successfully. Funds have been reserved pending M-Pesa disbursement.`,
        withdrawal: {
          id: withdrawalId,
          amountKsh: amount,
          phoneNumber: targetPhone,
          balanceType: 'referrals',
          status: 'pending',
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
    console.error('Withdrawal error:', err);
    return jsonError('Failed to process withdrawal request. Please try again.', 500);
  }
}
