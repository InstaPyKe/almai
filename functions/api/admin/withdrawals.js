// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/withdrawals
// Protected Administrator Withdrawal Queue & Payout Processing
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

/**
 * GET /api/admin/withdrawals
 * Fetch all pending and recent withdrawal requests
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get('status') || 'pending';

    let query = `
      SELECT wr.id, wr.user_id, wr.wallet_id, wr.amount_ksh, wr.phone_number,
             wr.status, wr.mpesa_receipt_number, wr.rejection_reason,
             wr.created_at, wr.processed_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone
      FROM withdrawal_requests wr
      JOIN users u ON wr.user_id = u.id
    `;

    if (filterStatus === 'pending') {
      query += ` WHERE wr.status = 'pending' ORDER BY wr.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY wr.created_at DESC LIMIT 100`;
    }

    const { results } = await env.DB.prepare(query).all();

    return jsonSuccess({
      withdrawals: results || []
    });

  } catch (err) {
    console.error('Admin fetch withdrawals error:', err);
    return jsonError('Failed to fetch withdrawal queue', 500);
  }
}

/**
 * POST /api/admin/withdrawals
 * Process withdrawal: Complete with verified M-Pesa reference OR Reject with refund
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const admin = auth.user;

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const { withdrawalId, action, mpesaReceipt, reason } = body;

  if (!withdrawalId || !action) {
    return jsonError('withdrawalId and action ("complete" | "reject") are required', 400);
  }

  try {
    // 1. Fetch withdrawal request
    const withdrawal = await env.DB.prepare(`
      SELECT wr.*, w.available_balance_ksh, w.reserved_balance_ksh
      FROM withdrawal_requests wr
      JOIN wallets w ON wr.wallet_id = w.id
      WHERE wr.id = ?
      LIMIT 1
    `).bind(withdrawalId).first();

    if (!withdrawal) {
      return jsonError('Withdrawal request not found', 404);
    }

    if (withdrawal.status !== 'pending') {
      return jsonError(`This withdrawal request is already marked as ${withdrawal.status}`, 409);
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (action === 'complete') {
      // Operator must provide the genuine M-Pesa confirmation receipt code
      if (!mpesaReceipt || mpesaReceipt.trim().length < 6) {
        return jsonError('Please enter the verified M-Pesa transaction reference code (e.g. QWE45RT67Y) to confirm payout disbursement', 400);
      }

      const cleanReceipt = mpesaReceipt.trim().toUpperCase();

      // Check duplicate receipt code across all completed withdrawals
      const existingReceipt = await env.DB.prepare(`
        SELECT id FROM withdrawal_requests WHERE mpesa_receipt_number = ? AND id != ? LIMIT 1
      `).bind(cleanReceipt, withdrawal.id).first();

      if (existingReceipt) {
        return jsonError('This M-Pesa receipt code has already been registered for another withdrawal', 409);
      }

      // 1. Update withdrawal status
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'completed',
            mpesa_receipt_number = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(cleanReceipt, admin.id, now, withdrawal.id).run();

      // 2. Safely deduct reserved funds and increment lifetime withdrawn
      await env.DB.prepare(`
        UPDATE wallets
        SET reserved_balance_ksh = reserved_balance_ksh - ?,
            lifetime_withdrawn_ksh = lifetime_withdrawn_ksh + ?,
            updated_at = ?
        WHERE id = ? AND reserved_balance_ksh >= ?
      `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();

      // 3. Record wallet ledger entry
      const txId = generateId('tx');
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

      // 4. Audit Log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'COMPLETE_WITHDRAWAL',
        targetType: 'withdrawal_request',
        targetId: withdrawal.id,
        details: { amountKsh: withdrawal.amount_ksh, phone: withdrawal.phone_number, mpesaReceipt: cleanReceipt },
        ip
      });

      return jsonSuccess({
        message: `Withdrawal payout marked completed with M-Pesa Ref ${cleanReceipt}.`,
        withdrawal: {
          id: withdrawal.id,
          status: 'completed',
          mpesaReceipt: cleanReceipt
        }
      });

    } else if (action === 'reject') {
      const rejectReason = reason || 'Withdrawal could not be processed. Funds refunded to wallet.';

      // 1. Update withdrawal record
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'rejected',
            rejection_reason = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, admin.id, now, withdrawal.id).run();

      // 2. Safe fund release back to available balance
      const newAvailable = withdrawal.available_balance_ksh + withdrawal.amount_ksh;
      await env.DB.prepare(`
        UPDATE wallets
        SET reserved_balance_ksh = reserved_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh + ?,
            updated_at = ?
        WHERE id = ? AND reserved_balance_ksh >= ?
      `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();

      // 3. Record wallet ledger refund
      const txId = generateId('tx');
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

      // 4. Audit Log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'REJECT_WITHDRAWAL',
        targetType: 'withdrawal_request',
        targetId: withdrawal.id,
        details: { reason: rejectReason, amountKsh: withdrawal.amount_ksh },
        ip
      });

      return jsonSuccess({
        message: 'Withdrawal rejected and funds refunded safely to partner wallet.',
        withdrawal: {
          id: withdrawal.id,
          status: 'rejected',
          refundedAmountKsh: withdrawal.amount_ksh
        }
      });

    } else {
      return jsonError('Invalid action. Must be "complete" or "reject".', 400);
    }

  } catch (err) {
    console.error('Process withdrawal error:', err);
    return jsonError('Failed to process withdrawal request. Please try again.', 500);
  }
}
