// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/withdrawals
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, generateId } from './_utils.js';

const MINIMUM_WITHDRAWAL_KSH = 100;

/**
 * GET /api/withdrawals
 * Get withdrawal history and current wallet balance
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  try {
    const wallet = await env.DB.prepare(`
      SELECT available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();

    const { results: requests } = await env.DB.prepare(`
      SELECT id, amount_ksh, phone_number, status, mpesa_receipt_number, rejection_reason, created_at, processed_at
      FROM withdrawal_requests
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 50
    `).bind(user.id).all();

    return jsonSuccess({
      wallet: wallet || { available_balance_ksh: 0, reserved_balance_ksh: 0, lifetime_withdrawn_ksh: 0 },
      minWithdrawalKsh: MINIMUM_WITHDRAWAL_KSH,
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

  const { amountKsh, phoneNumber } = body;

  const amount = parseInt(amountKsh, 10);
  if (isNaN(amount) || amount < MINIMUM_WITHDRAWAL_KSH) {
    return jsonError(`Minimum withdrawal amount is KSh ${MINIMUM_WITHDRAWAL_KSH}`, 400);
  }

  const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, '') : user.phone;
  if (!targetPhone || targetPhone.length < 9) {
    return jsonError('Valid M-Pesa phone number is required for payout', 400);
  }

  try {
    // 1. Fetch current wallet
    const wallet = await env.DB.prepare(`
      SELECT id, available_balance_ksh, reserved_balance_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();

    if (!wallet) {
      return jsonError('Wallet account not found', 404);
    }

    if (wallet.available_balance_ksh < amount) {
      return jsonError(`Insufficient available funds. Your available balance is KSh ${wallet.available_balance_ksh}, requested KSh ${amount}.`, 400);
    }

    const now = Math.floor(Date.now() / 1000);
    const withdrawalId = generateId('wth');
    const txId = generateId('wtx');
    const balanceAfter = wallet.available_balance_ksh - amount;

    // 2. Atomically reserve funds in wallet
    const updateResult = await env.DB.prepare(`
      UPDATE wallets
      SET available_balance_ksh = available_balance_ksh - ?,
          reserved_balance_ksh = reserved_balance_ksh + ?,
          updated_at = ?
      WHERE user_id = ? AND available_balance_ksh >= ?
    `).bind(amount, amount, now, user.id, amount).run();

    if (!updateResult.success || (updateResult.meta && updateResult.meta.changes === 0)) {
      return jsonError('Concurrent balance update conflict or insufficient funds. Please refresh and try again.', 409);
    }

    // 3. Create withdrawal request in pending status
    await env.DB.prepare(`
      INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
    `).bind(withdrawalId, user.id, wallet.id, amount, targetPhone, now).run();

    // 4. Record wallet transaction ledger entry
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
      `M-Pesa withdrawal request to ${targetPhone} placed on hold pending payout`,
      now
    ).run();

    return jsonSuccess({
      message: `Withdrawal request for KSh ${amount} submitted successfully. Funds have been reserved pending M-Pesa disbursement.`,
      withdrawal: {
        id: withdrawalId,
        amountKsh: amount,
        phoneNumber: targetPhone,
        status: 'pending',
        createdAt: now
      },
      wallet: {
        availableBalanceKsh: balanceAfter,
        reservedBalanceKsh: wallet.reserved_balance_ksh + amount
      }
    }, 201);

  } catch (err) {
    console.error('Withdrawal error:', err);
    return jsonError('Failed to process withdrawal request. Please try again.', 500);
  }
}
