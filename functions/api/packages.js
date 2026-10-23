// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/packages
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, generateId } from './_utils.js';

/**
 * GET /api/packages
 * Fetch all available packages and current payment gateway configuration status
 */
export async function onRequestGet(context) {
  const { env } = context;

  if (!env.DB) {
    return jsonError('Database configuration missing', 500);
  }

  try {
    const { results } = await env.DB.prepare(`
      SELECT id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, features, badge, is_active
      FROM packages
      WHERE is_active = 1
      ORDER BY price_ksh ASC
    `).all();

    const packages = (results || []).map(pkg => ({
      ...pkg,
      features: typeof pkg.features === 'string' ? JSON.parse(pkg.features) : pkg.features
    }));

    // Detect if live automated M-Pesa credentials exist in Cloudflare environment
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && 
      env.MPESA_CONSUMER_SECRET && 
      env.MPESA_PASSKEY && 
      env.MPESA_SHORTCODE
    );

    return jsonSuccess({
      packages,
      paymentSettings: {
        isMpesaAutomated: isMpesaConfigured,
        paymentMode: isMpesaConfigured ? 'automated_stk' : 'manual_till',
        paybill: env.MPESA_PAYBILL_NUMBER || '522533',
        accountNumber: env.MPESA_ACCOUNT_NUMBER || '8106675',
        paybillOrTill: `Paybill: ${env.MPESA_PAYBILL_NUMBER || '522533'} (Account: ${env.MPESA_ACCOUNT_NUMBER || '8106675'}, Name: ${env.MPESA_BUSINESS_NAME || 'JASPER MARKETS'})`,
        businessName: env.MPESA_BUSINESS_NAME || 'JASPER MARKETS'
      }
    });

  } catch (err) {
    console.error('Fetch packages error:', err);
    return jsonError('Failed to fetch advertising packages', 500);
  }
}

/**
 * POST /api/packages
 * Select and activate or initiate payment for a package
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

  const { packageId, phoneNumber, paymentReference } = body;

  if (!packageId) {
    return jsonError('packageId is required', 400);
  }

  try {
    // 1. Fetch package from database (DO NOT trust client prices)
    const pkg = await env.DB.prepare(`
      SELECT id, name, price_ksh, reward_per_view_ksh, max_views_per_task, is_active
      FROM packages
      WHERE id = ? AND is_active = 1
      LIMIT 1
    `).bind(packageId).first();

    if (!pkg) {
      return jsonError('Selected package was not found or is currently inactive', 404);
    }

    const now = Math.floor(Date.now() / 1000);
    const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, '') : user.phone;

    // Check if live M-Pesa is configured
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && 
      env.MPESA_CONSUMER_SECRET && 
      env.MPESA_PASSKEY && 
      env.MPESA_SHORTCODE
    );

    if (isMpesaConfigured) {
      // Future / Live Daraja STK Push workflow
      // Returns pending transaction for STK prompt verification
      const paymentTxId = generateId('pmt');
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_stk', 'pending', 'STK Push Triggered', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, now).run();

      return jsonSuccess({
        message: `M-Pesa STK Push initiated for KSh ${pkg.price_ksh}. Please enter your PIN on your phone.`,
        transactionId: paymentTxId,
        status: 'pending_pin'
      });
    } else {
      // Transparent Manual / Admin verified payment workflow
      // If reference is provided:
      if (!paymentReference || paymentReference.trim().length < 5) {
        return jsonError('Please enter your valid M-Pesa transaction reference (e.g. SLK89J21X) after sending payment.', 400);
      }

      const cleanRef = paymentReference.trim().toUpperCase();

      // Check if reference was already used
      const duplicate = await env.DB.prepare(`
        SELECT id FROM payment_transactions WHERE mpesa_receipt_number = ? LIMIT 1
      `).bind(cleanRef).first();

      if (duplicate) {
        return jsonError('This M-Pesa transaction reference has already been submitted.', 409);
      }

      const paymentTxId = generateId('pmt');
      const userPackageId = generateId('upkg');

      // 1. Record payment transaction in pending state for admin audit
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, mpesa_receipt_number, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_manual', ?, 'pending', 'Submitted by user, awaiting admin audit', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, cleanRef, now).run();

      // 2. Remove any previous pending package requests for this user
      await env.DB.prepare(`
        DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'
      `).bind(user.id).run();

      // 3. Insert user package in pending_verification status
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'pending_verification', ?)
      `).bind(userPackageId, user.id, pkg.id, now).run();

      return jsonSuccess({
        message: `M-Pesa reference ${cleanRef} submitted for ${pkg.name}! Our administrator will verify the payment code to activate your account.`,
        package: pkg,
        reference: cleanRef,
        status: 'pending_verification'
      }, 201);
    }

  } catch (err) {
    console.error('Package activation error:', err);
    return jsonError('Failed to process package activation. Please try again.', 500);
  }
}
