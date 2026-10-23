// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/payments
// Protected Administrator Payment Code Verification
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

/**
 * GET /api/admin/payments
 * Retrieve submitted M-Pesa transaction codes for package verification
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get('status') || 'pending';

    let query = `
      SELECT pt.id, pt.user_id, pt.package_id, pt.amount_ksh, pt.phone_number,
             pt.mpesa_receipt_number, pt.status, pt.notes, pt.verified_at, pt.created_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone,
             p.name as package_name, p.slug as package_slug, p.reward_per_view_ksh
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
    `;

    if (filterStatus === 'pending') {
      query += ` WHERE pt.status = 'pending' ORDER BY pt.created_at ASC LIMIT 100`;
    } else if (filterStatus === 'completed') {
      query += ` WHERE pt.status = 'completed' ORDER BY pt.created_at DESC LIMIT 100`;
    } else {
      query += ` ORDER BY pt.created_at DESC LIMIT 150`;
    }

    const { results } = await env.DB.prepare(query).all();

    return jsonSuccess({
      payments: results || []
    });

  } catch (err) {
    console.error('Admin fetch payments error:', err);
    return jsonError('Failed to fetch payment transactions for verification', 500);
  }
}

/**
 * POST /api/admin/payments
 * Verify or Reject user submitted payment transaction code
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

  const { paymentId, action, notes } = body;

  if (!paymentId || !action) {
    return jsonError('paymentId and action ("verify" | "reject") are required', 400);
  }

  try {
    // 1. Fetch payment transaction
    const payment = await env.DB.prepare(`
      SELECT pt.*, u.name as user_name, u.email as user_email, p.name as package_name
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
      WHERE pt.id = ?
      LIMIT 1
    `).bind(paymentId).first();

    if (!payment) {
      return jsonError('Payment transaction not found', 404);
    }

    if (payment.status !== 'pending') {
      return jsonError(`This payment transaction is already marked as ${payment.status}`, 409);
    }

    const now = Math.floor(Date.now() / 1000);
    const ip = request.headers.get('cf-connecting-ip') || '';

    if (action === 'verify') {
      const adminNote = notes || `Verified by Admin ${admin.name}`;

      // 1. Update payment transaction status to completed
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'completed',
            verified_at = ?,
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(now, adminNote, payment.id).run();

      // 2. Expire any previously active package for this user
      await env.DB.prepare(`
        UPDATE user_packages
        SET status = 'expired'
        WHERE user_id = ? AND status = 'active'
      `).bind(payment.user_id).run();

      // 3. Activate the new package
      const userPackageId = generateId('upkg');
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'active', ?)
      `).bind(userPackageId, payment.user_id, payment.package_id, now).run();

      // 4. Clean up any pending verification records for this user
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND id != ?
      `).bind(payment.user_id, userPackageId).run();

      // 5. Audit Log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'VERIFY_PAYMENT_CODE',
        targetType: 'payment_transaction',
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
          status: 'completed',
          mpesaReceipt: payment.mpesa_receipt_number
        }
      });

    } else if (action === 'reject') {
      const rejectReason = notes || 'M-Pesa transaction reference could not be verified with Safaricom';

      // 1. Mark transaction as failed
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'failed',
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, payment.id).run();

      // 2. Remove pending verification package record
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND package_id = ?
      `).bind(payment.user_id, payment.package_id).run();

      // 3. Audit Log
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'REJECT_PAYMENT_CODE',
        targetType: 'payment_transaction',
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
          status: 'failed',
          reason: rejectReason
        }
      });

    } else {
      return jsonError('Invalid action specified. Must be "verify" or "reject".', 400);
    }

  } catch (err) {
    console.error('Verify payment error:', err);
    return jsonError('Failed to process payment verification. Please try again.', 500);
  }
}
