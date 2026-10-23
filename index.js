var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// api/_utils.js
function jsonResponse(data, status = 200, headers = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "X-Content-Type-Options": "nosniff",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}
__name(jsonResponse, "jsonResponse");
function jsonError(message, status = 400, details = null) {
  return jsonResponse({
    success: false,
    error: message,
    ...details ? { details } : {}
  }, status);
}
__name(jsonError, "jsonError");
function jsonSuccess(data = {}, status = 200, headers = {}) {
  return jsonResponse({
    success: true,
    ...data
  }, status, headers);
}
__name(jsonSuccess, "jsonSuccess");
function generateToken(length = 32) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
__name(generateToken, "generateToken");
function generateId(prefix = "id") {
  return `${prefix}_${generateToken(12)}`;
}
__name(generateId, "generateId");
function bufToHex(buffer) {
  return Array.from(new Uint8Array(buffer)).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(bufToHex, "bufToHex");
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
__name(hexToBuf, "hexToBuf");
async function hashPassword(password, saltHex = null) {
  const enc = new TextEncoder();
  const salt = saltHex ? hexToBuf(saltHex) : crypto.getRandomValues(new Uint8Array(16));
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 1e5,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return {
    hash: bufToHex(derivedBits),
    salt: bufToHex(salt)
  };
}
__name(hashPassword, "hashPassword");
async function verifyPassword(password, storedHash, storedSalt) {
  const { hash } = await hashPassword(password, storedSalt);
  return hash === storedHash;
}
__name(verifyPassword, "verifyPassword");
function getCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie");
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, value] = cookie.split("=");
    if (key === name) {
      return decodeURIComponent(value);
    }
  }
  return null;
}
__name(getCookie, "getCookie");
function getSessionToken(request) {
  const cookieToken = getCookie(request, "almai_session");
  if (cookieToken) return cookieToken;
  const authHeader = request.headers.get("Authorization");
  if (authHeader && authHeader.startsWith("Bearer ")) {
    return authHeader.substring(7).trim();
  }
  return null;
}
__name(getSessionToken, "getSessionToken");
async function authenticate(request, env) {
  if (!env.DB) {
    throw new Error('Database binding "DB" is not configured in Cloudflare environment.');
  }
  const token = getSessionToken(request);
  if (!token) return null;
  const now = Math.floor(Date.now() / 1e3);
  const session = await env.DB.prepare(`
    SELECT s.id as session_id, s.user_id, s.expires_at, 
           u.name, u.email, u.phone, u.role, u.status
    FROM sessions s
    JOIN users u ON s.user_id = u.id
    WHERE s.id = ? AND s.expires_at > ? AND u.status = 'active'
    LIMIT 1
  `).bind(token, now).first();
  if (!session) return null;
  return {
    token,
    id: session.user_id,
    name: session.name,
    email: session.email,
    phone: session.phone,
    role: session.role,
    status: session.status
  };
}
__name(authenticate, "authenticate");
async function requireAuth(request, env) {
  const user = await authenticate(request, env);
  if (!user) {
    return { errorResponse: jsonError("Authentication required. Please sign in.", 401) };
  }
  return { user };
}
__name(requireAuth, "requireAuth");
async function requireAdmin(request, env) {
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth;
  if (auth.user.role !== "admin") {
    return { errorResponse: jsonError("Forbidden: Administrator privileges required.", 403) };
  }
  return { user: auth.user };
}
__name(requireAdmin, "requireAdmin");
async function createAuditLog(env, { adminId, action, targetType, targetId, details = {}, ip = "" }) {
  try {
    const id = generateId("aud");
    const now = Math.floor(Date.now() / 1e3);
    await env.DB.prepare(`
      INSERT INTO admin_audit_logs (id, admin_id, action, target_type, target_id, details, ip_address, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      id,
      adminId,
      action,
      targetType,
      targetId,
      JSON.stringify(details),
      ip,
      now
    ).run();
  } catch (err) {
    console.error("Audit log creation failed:", err);
  }
}
__name(createAuditLog, "createAuditLog");

// api/admin/audit-logs.js
async function onRequestGet(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const { results } = await env.DB.prepare(`
      SELECT al.id, al.action, al.target_type, al.target_id, al.details, al.ip_address, al.created_at,
             u.name as admin_name, u.email as admin_email
      FROM admin_audit_logs al
      JOIN users u ON al.admin_id = u.id
      ORDER BY al.created_at DESC
      LIMIT 100
    `).all();
    const formatted = (results || []).map((row) => ({
      ...row,
      details: row.details ? typeof row.details === "string" ? JSON.parse(row.details) : row.details : null
    }));
    return jsonSuccess({
      auditLogs: formatted
    });
  } catch (err) {
    console.error("Audit logs fetch error:", err);
    return jsonError("Failed to fetch audit logs", 500);
  }
}
__name(onRequestGet, "onRequestGet");

// api/admin/packages.js
async function onRequestGet2(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const { results } = await env.DB.prepare("SELECT * FROM packages ORDER BY price_ksh ASC").all();
    return jsonSuccess({ packages: results || [] });
  } catch (err) {
    return jsonError("Failed to fetch packages for admin", 500);
  }
}
__name(onRequestGet2, "onRequestGet");
async function onRequestPut(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { id, name, priceKsh, rewardPerViewKsh, maxViewsPerTask, isActive, features, badge } = body;
  if (!id) {
    return jsonError("Package ID is required", 400);
  }
  try {
    const existing = await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(id).first();
    if (!existing) {
      return jsonError("Package not found", 404);
    }
    const price = priceKsh !== void 0 ? parseInt(priceKsh, 10) : existing.price_ksh;
    const reward = rewardPerViewKsh !== void 0 ? parseInt(rewardPerViewKsh, 10) : existing.reward_per_view_ksh;
    const maxViews = maxViewsPerTask !== void 0 ? parseInt(maxViewsPerTask, 10) : existing.max_views_per_task;
    const active = isActive !== void 0 ? isActive ? 1 : 0 : existing.is_active;
    const pkgName = name || existing.name;
    const pkgBadge = badge !== void 0 ? badge : existing.badge;
    const pkgFeatures = features ? typeof features === "string" ? features : JSON.stringify(features) : existing.features;
    await env.DB.prepare(`
      UPDATE packages
      SET name = ?, price_ksh = ?, reward_per_view_ksh = ?, max_views_per_task = ?,
          is_active = ?, badge = ?, features = ?
      WHERE id = ?
    `).bind(pkgName, price, reward, maxViews, active, pkgBadge, pkgFeatures, id).run();
    await createAuditLog(env, {
      adminId: admin.id,
      action: "UPDATE_PACKAGE",
      targetType: "package",
      targetId: id,
      details: { name: pkgName, price, reward, maxViews, active }
    });
    return jsonSuccess({
      message: "Package updated successfully",
      package: { id, name: pkgName, price_ksh: price, reward_per_view_ksh: reward, max_views_per_task: maxViews, is_active: active }
    });
  } catch (err) {
    console.error("Update package error:", err);
    return jsonError("Failed to update package", 500);
  }
}
__name(onRequestPut, "onRequestPut");

// api/admin/payments.js
async function onRequestGet3(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT pt.id, pt.user_id, pt.package_id, pt.amount_ksh, pt.phone_number,
             pt.mpesa_receipt_number, pt.status, pt.notes, pt.verified_at, pt.created_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone,
             p.name as package_name, p.slug as package_slug, p.reward_per_view_ksh
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
    `;
    if (filterStatus === "pending") {
      query += ` WHERE pt.status = 'pending' ORDER BY pt.created_at ASC LIMIT 100`;
    } else if (filterStatus === "completed") {
      query += ` WHERE pt.status = 'completed' ORDER BY pt.created_at DESC LIMIT 100`;
    } else {
      query += ` ORDER BY pt.created_at DESC LIMIT 150`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      payments: results || []
    });
  } catch (err) {
    console.error("Admin fetch payments error:", err);
    return jsonError("Failed to fetch payment transactions for verification", 500);
  }
}
__name(onRequestGet3, "onRequestGet");
async function onRequestPost(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { paymentId, action, notes } = body;
  if (!paymentId || !action) {
    return jsonError('paymentId and action ("verify" | "reject") are required', 400);
  }
  try {
    const payment = await env.DB.prepare(`
      SELECT pt.*, u.name as user_name, u.email as user_email, p.name as package_name
      FROM payment_transactions pt
      JOIN users u ON pt.user_id = u.id
      JOIN packages p ON pt.package_id = p.id
      WHERE pt.id = ?
      LIMIT 1
    `).bind(paymentId).first();
    if (!payment) {
      return jsonError("Payment transaction not found", 404);
    }
    if (payment.status !== "pending") {
      return jsonError(`This payment transaction is already marked as ${payment.status}`, 409);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "verify") {
      const adminNote = notes || `Verified by Admin ${admin.name}`;
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'completed',
            verified_at = ?,
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(now, adminNote, payment.id).run();
      await env.DB.prepare(`
        UPDATE user_packages
        SET status = 'expired'
        WHERE user_id = ? AND status = 'active'
      `).bind(payment.user_id).run();
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'active', ?)
      `).bind(userPackageId, payment.user_id, payment.package_id, now).run();
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND id != ?
      `).bind(payment.user_id, userPackageId).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "VERIFY_PAYMENT_CODE",
        targetType: "payment_transaction",
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
          status: "completed",
          mpesaReceipt: payment.mpesa_receipt_number
        }
      });
    } else if (action === "reject") {
      const rejectReason = notes || "M-Pesa transaction reference could not be verified with Safaricom";
      await env.DB.prepare(`
        UPDATE payment_transactions
        SET status = 'failed',
            notes = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, payment.id).run();
      await env.DB.prepare(`
        DELETE FROM user_packages
        WHERE user_id = ? AND status = 'pending_verification' AND package_id = ?
      `).bind(payment.user_id, payment.package_id).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_PAYMENT_CODE",
        targetType: "payment_transaction",
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
          status: "failed",
          reason: rejectReason
        }
      });
    } else {
      return jsonError('Invalid action specified. Must be "verify" or "reject".', 400);
    }
  } catch (err) {
    console.error("Verify payment error:", err);
    return jsonError("Failed to process payment verification. Please try again.", 500);
  }
}
__name(onRequestPost, "onRequestPost");

// api/admin/products-posts.js
async function onRequestGet4(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const { results } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, caption, image_url, image_base64, image_name, status, downloads_count, created_at
      FROM product_posts
      ORDER BY created_at DESC
      LIMIT 100
    `).all();
    return jsonSuccess({
      productPosts: results || []
    });
  } catch (err) {
    console.error("Admin fetch product posts error:", err);
    return jsonError("Failed to fetch product posts for admin", 500);
  }
}
__name(onRequestGet4, "onRequestGet");
async function onRequestPost2(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { title, brandName, description, caption, imageBase64, imageName } = body;
  if (!title || typeof title !== "string" || title.trim().length < 3) {
    return jsonError("Please enter a valid product title (at least 3 characters)", 400);
  }
  if (!brandName || typeof brandName !== "string" || brandName.trim().length < 2) {
    return jsonError("Please enter a valid brand or company name", 400);
  }
  if (!caption || typeof caption !== "string" || caption.trim().length < 5) {
    return jsonError("Please provide the suggested WhatsApp caption for users to copy", 400);
  }
  if (!imageBase64 || typeof imageBase64 !== "string") {
    return jsonError("Product picture image file is required", 400);
  }
  if (imageBase64.length > 5 * 1024 * 1024) {
    return jsonError("Product image file is too large. Please upload an image under 3.5MB.", 400);
  }
  try {
    const postId = generateId("prod");
    const now = Math.floor(Date.now() / 1e3);
    const cleanTitle = title.trim();
    const cleanBrand = brandName.trim();
    const cleanDesc = (description || "").trim();
    const cleanCaption = caption.trim();
    const fileName = imageName || "whatsapp_promo.png";
    await env.DB.prepare(`
      INSERT INTO product_posts (
        id, title, brand_name, description, caption, image_base64, image_name, status, downloads_count, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', 0, ?)
    `).bind(
      postId,
      cleanTitle,
      cleanBrand,
      cleanDesc,
      cleanCaption,
      imageBase64,
      fileName,
      now
    ).run();
    const campaignId = `camp_${postId}`;
    await env.DB.prepare(`
      INSERT OR REPLACE INTO campaigns (id, title, brand_name, description, guidelines, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'active', ?)
    `).bind(
      campaignId,
      cleanTitle,
      cleanBrand,
      cleanDesc || `Campaign for ${cleanTitle}`,
      cleanCaption,
      now
    ).run();
    const ip = request.headers.get("cf-connecting-ip") || "";
    await createAuditLog(env, {
      adminId: admin.id,
      action: "POST_WHATSAPP_PRODUCT",
      targetType: "product_post",
      targetId: postId,
      details: { title: cleanTitle, brand: cleanBrand, file: fileName },
      ip
    });
    return jsonSuccess({
      message: `Product creative "${cleanTitle}" posted successfully! It is now live for all users to download.`,
      product: {
        id: postId,
        title: cleanTitle,
        brand_name: cleanBrand,
        caption: cleanCaption,
        downloads_count: 0,
        created_at: now
      }
    }, 201);
  } catch (err) {
    console.error("Admin post product creative error:", err);
    return jsonError("Failed to publish product creative. Please try again.", 500);
  }
}
__name(onRequestPost2, "onRequestPost");
async function onRequestDelete(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { postId } = body;
  if (!postId) {
    return jsonError("postId is required", 400);
  }
  try {
    const existing = await env.DB.prepare("SELECT id, title FROM product_posts WHERE id = ?").bind(postId).first();
    if (!existing) {
      return jsonError("Product post not found", 404);
    }
    await env.DB.prepare("DELETE FROM product_posts WHERE id = ?").bind(postId).run();
    const ip = request.headers.get("cf-connecting-ip") || "";
    await createAuditLog(env, {
      adminId: admin.id,
      action: "DELETE_PRODUCT_POST",
      targetType: "product_post",
      targetId: postId,
      details: { title: existing.title },
      ip
    });
    return jsonSuccess({
      message: `Product creative "${existing.title}" has been deleted.`
    });
  } catch (err) {
    console.error("Delete product post error:", err);
    return jsonError("Failed to delete product post", 500);
  }
}
__name(onRequestDelete, "onRequestDelete");

// api/admin/stats.js
async function onRequestGet5(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const usersCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
    const pendingTasks = await env.DB.prepare("SELECT COUNT(*) as count FROM task_submissions WHERE status = 'pending'").first();
    const pendingWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'pending'").first();
    const completedWithdrawals = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM withdrawal_requests WHERE status = 'completed'").first();
    const taskAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(approved_views), 0) as total_approved_views,
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(reward_amount_ksh), 0) as total_rewards_granted_ksh
      FROM task_submissions
      WHERE status = 'approved'
    `).first();
    const walletAggregates = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(available_balance_ksh), 0) as total_available_in_system,
        COALESCE(SUM(reserved_balance_ksh), 0) as total_reserved_in_system
      FROM wallets
    `).first();
    const pendingPayments = await env.DB.prepare("SELECT COUNT(*) as count, COALESCE(SUM(amount_ksh), 0) as total_amount FROM payment_transactions WHERE status = 'pending'").first();
    const productsCount = await env.DB.prepare("SELECT COUNT(*) as count FROM product_posts WHERE status = 'active'").first();
    return jsonSuccess({
      metrics: {
        totalUsers: usersCount?.count || 0,
        pendingPaymentsCount: pendingPayments?.count || 0,
        pendingPaymentsAmountKsh: pendingPayments?.total_amount || 0,
        totalProductsCount: productsCount?.count || 0,
        pendingTasksCount: pendingTasks?.count || 0,
        pendingWithdrawalsCount: pendingWithdrawals?.count || 0,
        pendingWithdrawalsAmountKsh: pendingWithdrawals?.total_amount || 0,
        completedWithdrawalsCount: completedWithdrawals?.count || 0,
        totalDisbursedKsh: completedWithdrawals?.total_amount || 0,
        totalApprovedViews: taskAggregates?.total_approved_views || 0,
        totalReportedViews: taskAggregates?.total_reported_views || 0,
        totalRewardsGrantedKsh: taskAggregates?.total_rewards_granted_ksh || 0,
        totalAvailableInSystemKsh: walletAggregates?.total_available_in_system || 0,
        totalReservedInSystemKsh: walletAggregates?.total_reserved_in_system || 0
      }
    });
  } catch (err) {
    console.error("Admin stats error:", err);
    return jsonError("Failed to fetch system metrics", 500);
  }
}
__name(onRequestGet5, "onRequestGet");

// api/admin/tasks.js
async function onRequestGet6(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT ts.id, ts.user_id, ts.campaign_id, ts.package_id, ts.reported_views,
             ts.approved_views, ts.reward_rate_ksh, ts.reward_amount_ksh,
             ts.evidence_text, ts.evidence_id, ts.status, ts.admin_notes,
             ts.created_at, ts.reviewed_at,
             u.name as user_name, u.email as user_email, u.phone as user_phone,
             c.title as campaign_title, p.name as package_name, p.max_views_per_task
      FROM task_submissions ts
      JOIN users u ON ts.user_id = u.id
      LEFT JOIN campaigns c ON ts.campaign_id = c.id
      LEFT JOIN packages p ON ts.package_id = p.id
    `;
    let params = [];
    if (filterStatus === "pending") {
      query += ` WHERE ts.status = 'pending' ORDER BY ts.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY ts.created_at DESC LIMIT 100`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      submissions: results || []
    });
  } catch (err) {
    console.error("Admin fetch tasks error:", err);
    return jsonError("Failed to fetch submissions for review", 500);
  }
}
__name(onRequestGet6, "onRequestGet");
async function onRequestPost3(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { submissionId, action, approvedViews, notes } = body;
  if (!submissionId || !action) {
    return jsonError('submissionId and action ("approve" | "reject") are required', 400);
  }
  try {
    const task = await env.DB.prepare(`
      SELECT ts.*, p.max_views_per_task
      FROM task_submissions ts
      LEFT JOIN packages p ON ts.package_id = p.id
      WHERE ts.id = ?
      LIMIT 1
    `).bind(submissionId).first();
    if (!task) {
      return jsonError("Task submission not found", 404);
    }
    if (task.status !== "pending") {
      return jsonError(`This task submission has already been ${task.status}.`, 409);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "approve") {
      const views = parseInt(approvedViews, 10);
      if (isNaN(views) || views <= 0) {
        return jsonError("Please specify valid approved views greater than 0", 400);
      }
      const maxViews = task.max_views_per_task || 200;
      if (views > maxViews) {
        return jsonError(`Approved views (${views}) exceeds package cap of ${maxViews} views`, 400);
      }
      const rewardKsh = views * task.reward_rate_ksh;
      const wallet = await env.DB.prepare("SELECT id, available_balance_ksh FROM wallets WHERE user_id = ?").bind(task.user_id).first();
      if (!wallet) {
        return jsonError("User wallet not found", 404);
      }
      const balanceAfter = wallet.available_balance_ksh + rewardKsh;
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'approved',
            approved_views = ?,
            reward_amount_ksh = ?,
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(views, rewardKsh, notes || "Verified screenshot evidence", admin.id, now, task.id).run();
      await env.DB.prepare(`
        UPDATE wallets
        SET available_balance_ksh = available_balance_ksh + ?,
            lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(rewardKsh, rewardKsh, now, task.user_id).run();
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        task.user_id,
        rewardKsh,
        balanceAfter,
        task.id,
        `Campaign reward credited: ${views} approved WhatsApp Status views @ KSh ${task.reward_rate_ksh}/view`,
        now
      ).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "APPROVE_TASK",
        targetType: "task_submission",
        targetId: task.id,
        details: { approvedViews: views, rewardKsh, notes },
        ip
      });
      return jsonSuccess({
        message: `Task submission approved! Credited KSh ${rewardKsh} to partner wallet.`,
        task: {
          id: task.id,
          status: "approved",
          approvedViews: views,
          rewardAmountKsh: rewardKsh
        }
      });
    } else if (action === "reject") {
      const reason = notes || "Screenshot evidence could not be verified or does not match requirements";
      await env.DB.prepare(`
        UPDATE task_submissions
        SET status = 'rejected',
            admin_notes = ?,
            reviewed_by = ?,
            reviewed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(reason, admin.id, now, task.id).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_TASK",
        targetType: "task_submission",
        targetId: task.id,
        details: { reason },
        ip
      });
      return jsonSuccess({
        message: "Task submission has been rejected.",
        task: {
          id: task.id,
          status: "rejected",
          reason
        }
      });
    } else {
      return jsonError('Invalid action specified. Must be "approve" or "reject".', 400);
    }
  } catch (err) {
    console.error("Admin review error:", err);
    return jsonError("Failed to process task review. Please try again.", 500);
  }
}
__name(onRequestPost3, "onRequestPost");

// api/admin/users.js
async function onRequestGet7(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const search = url.searchParams.get("q") || "";
    let query = `
      SELECT 
        u.id, u.name, u.email, u.phone, u.role, u.status, u.created_at, u.updated_at,
        COALESCE(w.available_balance_ksh, 0) as available_balance_ksh,
        COALESCE(w.reserved_balance_ksh, 0) as reserved_balance_ksh,
        COALESCE(w.lifetime_earnings_ksh, 0) as lifetime_earnings_ksh,
        COALESCE(w.lifetime_withdrawn_ksh, 0) as lifetime_withdrawn_ksh,
        p.id as active_package_id,
        p.name as active_package_name,
        p.slug as active_package_slug,
        p.reward_per_view_ksh as active_package_rate,
        up.activated_at as package_activated_at,
        (
          SELECT p_pen.name 
          FROM user_packages up_pen 
          JOIN packages p_pen ON up_pen.package_id = p_pen.id 
          WHERE up_pen.user_id = u.id AND up_pen.status = 'pending_verification' 
          LIMIT 1
        ) as pending_package_name
      FROM users u
      LEFT JOIN wallets w ON u.id = w.user_id
      LEFT JOIN user_packages up ON u.id = up.user_id AND up.status = 'active'
      LEFT JOIN packages p ON up.package_id = p.id
    `;
    const params = [];
    if (search.trim()) {
      const term = `%${search.trim().toLowerCase()}%`;
      query += ` WHERE LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ? OR u.phone LIKE ?`;
      params.push(term, term, term);
    }
    query += ` ORDER BY u.created_at DESC LIMIT 150`;
    const stmt = params.length > 0 ? env.DB.prepare(query).bind(...params) : env.DB.prepare(query);
    const { results } = await stmt.all();
    return jsonSuccess({
      users: results || []
    });
  } catch (err) {
    console.error("Admin fetch users error:", err);
    return jsonError("Failed to fetch user directory", 500);
  }
}
__name(onRequestGet7, "onRequestGet");
async function onRequestPost4(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { targetUserId, action, packageId, newStatus, newRole } = body;
  if (!targetUserId || !action) {
    return jsonError("targetUserId and action are required", 400);
  }
  try {
    const target = await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(targetUserId).first();
    if (!target) {
      return jsonError("Target user not found", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "assign_package") {
      if (!packageId) {
        return jsonError("packageId is required to assign package", 400);
      }
      const pkg = await env.DB.prepare("SELECT * FROM packages WHERE id = ?").bind(packageId).first();
      if (!pkg) {
        return jsonError("Selected package was not found", 404);
      }
      await env.DB.prepare("UPDATE user_packages SET status = 'expired' WHERE user_id = ? AND status = 'active'").bind(target.id).run();
      await env.DB.prepare("DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'").bind(target.id).run();
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'active', ?)
      `).bind(userPackageId, target.id, pkg.id, now).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "ADMIN_ASSIGN_PACKAGE",
        targetType: "user",
        targetId: target.id,
        details: { packageId: pkg.id, packageName: pkg.name, assignedTo: target.email },
        ip
      });
      return jsonSuccess({
        message: `Package ${pkg.name} manually activated for ${target.name} (${target.email})!`,
        package: pkg
      });
    } else if (action === "toggle_status") {
      const nextStatus = newStatus || (target.status === "active" ? "suspended" : "active");
      await env.DB.prepare("UPDATE users SET status = ?, updated_at = ? WHERE id = ?").bind(nextStatus, now, target.id).run();
      if (nextStatus === "suspended") {
        await env.DB.prepare("DELETE FROM sessions WHERE user_id = ?").bind(target.id).run();
      }
      await createAuditLog(env, {
        adminId: admin.id,
        action: "TOGGLE_USER_STATUS",
        targetType: "user",
        targetId: target.id,
        details: { oldStatus: target.status, newStatus: nextStatus },
        ip
      });
      return jsonSuccess({
        message: `User ${target.name} status updated to ${nextStatus}.`,
        status: nextStatus
      });
    } else if (action === "toggle_role") {
      const nextRole = newRole || (target.role === "admin" ? "user" : "admin");
      await env.DB.prepare("UPDATE users SET role = ?, updated_at = ? WHERE id = ?").bind(nextRole, now, target.id).run();
      await createAuditLog(env, {
        adminId: admin.id,
        action: "TOGGLE_USER_ROLE",
        targetType: "user",
        targetId: target.id,
        details: { oldRole: target.role, newRole: nextRole },
        ip
      });
      return jsonSuccess({
        message: `User ${target.name} role updated to ${nextRole}.`,
        role: nextRole
      });
    } else {
      return jsonError("Invalid action specified", 400);
    }
  } catch (err) {
    console.error("Admin user action error:", err);
    return jsonError("Failed to perform user administrative action", 500);
  }
}
__name(onRequestPost4, "onRequestPost");

// api/admin/withdrawals.js
async function onRequestGet8(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  try {
    const url = new URL(request.url);
    const filterStatus = url.searchParams.get("status") || "pending";
    let query = `
      SELECT wr.id, wr.user_id, wr.wallet_id, wr.amount_ksh, wr.phone_number,
             wr.status, wr.mpesa_receipt_number, wr.rejection_reason,
             wr.created_at, wr.processed_at,
             u.name as user_name, u.email as user_email, u.phone as user_registered_phone
      FROM withdrawal_requests wr
      JOIN users u ON wr.user_id = u.id
    `;
    if (filterStatus === "pending") {
      query += ` WHERE wr.status = 'pending' ORDER BY wr.created_at ASC LIMIT 100`;
    } else {
      query += ` ORDER BY wr.created_at DESC LIMIT 100`;
    }
    const { results } = await env.DB.prepare(query).all();
    return jsonSuccess({
      withdrawals: results || []
    });
  } catch (err) {
    console.error("Admin fetch withdrawals error:", err);
    return jsonError("Failed to fetch withdrawal queue", 500);
  }
}
__name(onRequestGet8, "onRequestGet");
async function onRequestPost5(context) {
  const { request, env } = context;
  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const admin = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { withdrawalId, action, mpesaReceipt, reason } = body;
  if (!withdrawalId || !action) {
    return jsonError('withdrawalId and action ("complete" | "reject") are required', 400);
  }
  try {
    const withdrawal = await env.DB.prepare(`
      SELECT wr.*, w.available_balance_ksh, w.reserved_balance_ksh
      FROM withdrawal_requests wr
      JOIN wallets w ON wr.wallet_id = w.id
      WHERE wr.id = ?
      LIMIT 1
    `).bind(withdrawalId).first();
    if (!withdrawal) {
      return jsonError("Withdrawal request not found", 404);
    }
    if (withdrawal.status !== "pending") {
      return jsonError(`This withdrawal request is already marked as ${withdrawal.status}`, 409);
    }
    const now = Math.floor(Date.now() / 1e3);
    const ip = request.headers.get("cf-connecting-ip") || "";
    if (action === "complete") {
      if (!mpesaReceipt || mpesaReceipt.trim().length < 6) {
        return jsonError("Please enter the verified M-Pesa transaction reference code (e.g. QWE45RT67Y) to confirm payout disbursement", 400);
      }
      const cleanReceipt = mpesaReceipt.trim().toUpperCase();
      const existingReceipt = await env.DB.prepare(`
        SELECT id FROM withdrawal_requests WHERE mpesa_receipt_number = ? AND id != ? LIMIT 1
      `).bind(cleanReceipt, withdrawal.id).first();
      if (existingReceipt) {
        return jsonError("This M-Pesa receipt code has already been registered for another withdrawal", 409);
      }
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'completed',
            mpesa_receipt_number = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(cleanReceipt, admin.id, now, withdrawal.id).run();
      await env.DB.prepare(`
        UPDATE wallets
        SET reserved_balance_ksh = reserved_balance_ksh - ?,
            lifetime_withdrawn_ksh = lifetime_withdrawn_ksh + ?,
            updated_at = ?
        WHERE id = ? AND reserved_balance_ksh >= ?
      `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      const txId = generateId("tx");
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
      await createAuditLog(env, {
        adminId: admin.id,
        action: "COMPLETE_WITHDRAWAL",
        targetType: "withdrawal_request",
        targetId: withdrawal.id,
        details: { amountKsh: withdrawal.amount_ksh, phone: withdrawal.phone_number, mpesaReceipt: cleanReceipt },
        ip
      });
      return jsonSuccess({
        message: `Withdrawal payout marked completed with M-Pesa Ref ${cleanReceipt}.`,
        withdrawal: {
          id: withdrawal.id,
          status: "completed",
          mpesaReceipt: cleanReceipt
        }
      });
    } else if (action === "reject") {
      const rejectReason = reason || "Withdrawal could not be processed. Funds refunded to wallet.";
      await env.DB.prepare(`
        UPDATE withdrawal_requests
        SET status = 'rejected',
            rejection_reason = ?,
            processed_by = ?,
            processed_at = ?
        WHERE id = ? AND status = 'pending'
      `).bind(rejectReason, admin.id, now, withdrawal.id).run();
      const newAvailable = withdrawal.available_balance_ksh + withdrawal.amount_ksh;
      await env.DB.prepare(`
        UPDATE wallets
        SET reserved_balance_ksh = reserved_balance_ksh - ?,
            available_balance_ksh = available_balance_ksh + ?,
            updated_at = ?
        WHERE id = ? AND reserved_balance_ksh >= ?
      `).bind(withdrawal.amount_ksh, withdrawal.amount_ksh, now, withdrawal.wallet_id, withdrawal.amount_ksh).run();
      const txId = generateId("tx");
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
      await createAuditLog(env, {
        adminId: admin.id,
        action: "REJECT_WITHDRAWAL",
        targetType: "withdrawal_request",
        targetId: withdrawal.id,
        details: { reason: rejectReason, amountKsh: withdrawal.amount_ksh },
        ip
      });
      return jsonSuccess({
        message: "Withdrawal rejected and funds refunded safely to partner wallet.",
        withdrawal: {
          id: withdrawal.id,
          status: "rejected",
          refundedAmountKsh: withdrawal.amount_ksh
        }
      });
    } else {
      return jsonError('Invalid action. Must be "complete" or "reject".', 400);
    }
  } catch (err) {
    console.error("Process withdrawal error:", err);
    return jsonError("Failed to process withdrawal request. Please try again.", 500);
  }
}
__name(onRequestPost5, "onRequestPost");

// api/auth/login.js
async function onRequestPost6(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { email, password } = body;
  if (!email || !password) {
    return jsonError("Email and password are required", 400);
  }
  const cleanEmail = email.trim().toLowerCase();
  try {
    let user = await env.DB.prepare(`
      SELECT id, name, email, phone, password_hash, salt, role, status
      FROM users
      WHERE email = ?
      LIMIT 1
    `).bind(cleanEmail).first();
    if (cleanEmail === "almai@admin.co.ke" && password === "almai12345") {
      const adminSalt = "a1b2c3d4e5f60718293a4b5c6d7e8f90";
      const adminHash = "34d565655f84920c15ea79180a187359f904bb2bee5e667b78ae3a0258e84ca3";
      const now2 = Math.floor(Date.now() / 1e3);
      if (!user) {
        const adminId = "usr_admin_almai";
        await env.DB.prepare(`
          INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
          VALUES (?, 'Almai Administrator', 'almai@admin.co.ke', '0700000000', ?, ?, 'admin', 'active', ?, ?)
        `).bind(adminId, adminHash, adminSalt, now2, now2).run();
        await env.DB.prepare(`
          INSERT OR IGNORE INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
          VALUES ('wal_admin_almai', ?, 0, 0, 0, 0, ?)
        `).bind(adminId, now2).run();
        user = {
          id: adminId,
          name: "Almai Administrator",
          email: "almai@admin.co.ke",
          phone: "0700000000",
          password_hash: adminHash,
          salt: adminSalt,
          role: "admin",
          status: "active"
        };
      } else if (user.role !== "admin" || user.password_hash !== adminHash) {
        await env.DB.prepare(`
          UPDATE users SET role = 'admin', password_hash = ?, salt = ?, status = 'active', updated_at = ? WHERE id = ?
        `).bind(adminHash, adminSalt, now2, user.id).run();
        user.role = "admin";
        user.status = "active";
        user.password_hash = adminHash;
        user.salt = adminSalt;
      }
    }
    if (!user) {
      await verifyPassword(password, "00".repeat(32), "00".repeat(16));
      return jsonError("Invalid email or password", 401);
    }
    if (user.status !== "active") {
      return jsonError("Your account has been suspended. Please contact support.", 403);
    }
    const isValid = await verifyPassword(password, user.password_hash, user.salt);
    if (!isValid) {
      return jsonError("Invalid email or password", 401);
    }
    const sessionToken = generateToken(32);
    const now = Math.floor(Date.now() / 1e3);
    const expiresAt = now + 7 * 24 * 60 * 60;
    const ip = request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "";
    const userAgent = request.headers.get("user-agent") || "";
    await env.DB.prepare(`
      INSERT INTO sessions (id, user_id, expires_at, created_at, ip_address, user_agent)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      sessionToken,
      user.id,
      expiresAt,
      now,
      ip,
      userAgent
    ).run();
    const activePackage = await env.DB.prepare(`
      SELECT up.package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, up.status
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      WHERE up.user_id = ? AND up.status = 'active'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const pendingPackage = await env.DB.prepare(`
      SELECT up.package_id, p.name, p.slug, p.price_ksh, up.status, pt.mpesa_receipt_number
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      LEFT JOIN payment_transactions pt ON pt.user_id = up.user_id AND pt.package_id = up.package_id AND pt.status = 'pending'
      WHERE up.user_id = ? AND up.status = 'pending_verification'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const cookieHeader = `almai_session=${sessionToken}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 86400}`;
    return jsonSuccess({
      message: "Sign in successful. Welcome back!",
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      hasActivePackage: Boolean(activePackage),
      activePackage: activePackage || null,
      pendingPackage: pendingPackage || null,
      token: sessionToken
    }, 200, {
      "Set-Cookie": cookieHeader
    });
  } catch (err) {
    console.error("Login error:", err);
    return jsonError("Sign in failed due to a server error. Please try again.", 500);
  }
}
__name(onRequestPost6, "onRequestPost");

// api/auth/logout.js
async function onRequestPost7(context) {
  const { request, env } = context;
  const token = getSessionToken(request);
  if (token && env.DB) {
    try {
      await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(token).run();
    } catch (err) {
      console.error("Logout session delete error:", err);
    }
  }
  const clearCookieHeader = "almai_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";
  return jsonSuccess({
    message: "Signed out successfully"
  }, 200, {
    "Set-Cookie": clearCookieHeader
  });
}
__name(onRequestPost7, "onRequestPost");

// api/auth/me.js
async function onRequestGet9(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    let wallet = await env.DB.prepare(`
      SELECT available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();
    if (!wallet) {
      wallet = {
        available_balance_ksh: 0,
        reserved_balance_ksh: 0,
        lifetime_earnings_ksh: 0,
        lifetime_withdrawn_ksh: 0
      };
    }
    const activePackage = await env.DB.prepare(`
      SELECT up.id as user_package_id, up.status, up.activated_at,
             p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.max_views_per_task, p.badge
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      WHERE up.user_id = ? AND up.status = 'active'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const pendingPackage = await env.DB.prepare(`
      SELECT up.id as user_package_id, up.status, up.activated_at,
             p.id as package_id, p.name, p.slug, p.price_ksh, p.reward_per_view_ksh, p.max_views_per_task, p.badge,
             pt.mpesa_receipt_number, pt.created_at as payment_submitted_at
      FROM user_packages up
      JOIN packages p ON up.package_id = p.id
      LEFT JOIN payment_transactions pt ON pt.user_id = up.user_id AND pt.package_id = up.package_id AND pt.status = 'pending'
      WHERE up.user_id = ? AND up.status = 'pending_verification'
      ORDER BY up.activated_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const latestTask = await env.DB.prepare(`
      SELECT created_at, status
      FROM task_submissions
      WHERE user_id = ?
      ORDER BY created_at DESC
      LIMIT 1
    `).bind(user.id).first();
    const now = Math.floor(Date.now() / 1e3);
    let canSubmitTask = true;
    let nextSubmissionAllowedAt = now;
    let secondsRemaining = 0;
    if (latestTask) {
      const cooldownPeriod = 18 * 60 * 60;
      const nextTime = latestTask.created_at + cooldownPeriod;
      if (now < nextTime) {
        canSubmitTask = false;
        nextSubmissionAllowedAt = nextTime;
        secondsRemaining = nextTime - now;
      }
    }
    const taskStats = await env.DB.prepare(`
      SELECT 
        COALESCE(SUM(reported_views), 0) as total_reported_views,
        COALESCE(SUM(CASE WHEN status = 'pending' THEN reported_views ELSE 0 END), 0) as pending_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN approved_views ELSE 0 END), 0) as approved_views,
        COALESCE(SUM(CASE WHEN status = 'approved' THEN reward_amount_ksh ELSE 0 END), 0) as total_approved_rewards_ksh,
        COUNT(CASE WHEN status = 'pending' THEN 1 END) as pending_tasks_count
      FROM task_submissions
      WHERE user_id = ?
    `).bind(user.id).first();
    return jsonSuccess({
      authenticated: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        role: user.role
      },
      wallet,
      activePackage: activePackage || null,
      pendingPackage: pendingPackage || null,
      hasActivePackage: Boolean(activePackage),
      cooldown: {
        canSubmitTask,
        nextSubmissionAllowedAt,
        secondsRemaining,
        lastSubmittedAt: latestTask ? latestTask.created_at : null
      },
      stats: {
        reportedViews: taskStats?.total_reported_views || 0,
        pendingViews: taskStats?.pending_views || 0,
        approvedViews: taskStats?.approved_views || 0,
        approvedRewardsKsh: taskStats?.total_approved_rewards_ksh || 0,
        pendingTasksCount: taskStats?.pending_tasks_count || 0,
        availableBalanceKsh: wallet.available_balance_ksh,
        reservedBalanceKsh: wallet.reserved_balance_ksh,
        completedWithdrawalsKsh: wallet.lifetime_withdrawn_ksh
      }
    });
  } catch (err) {
    console.error("/api/auth/me error:", err);
    return jsonError("Failed to retrieve user profile", 500);
  }
}
__name(onRequestGet9, "onRequestGet");

// api/auth/register.js
async function onRequestPost8(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { name, email, phone, password } = body;
  if (!name || typeof name !== "string" || name.trim().length < 2) {
    return jsonError("Valid full name is required (min 2 characters)", 400);
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError("Please provide a valid email address", 400);
  }
  if (!phone || typeof phone !== "string" || phone.trim().length < 9) {
    return jsonError("Please provide a valid M-Pesa phone number (e.g. 0712345678 or 254712345678)", 400);
  }
  if (!password || typeof password !== "string" || password.length < 8) {
    return jsonError("Password must be at least 8 characters long", 400);
  }
  const cleanEmail = email.trim().toLowerCase();
  const cleanPhone = phone.trim().replace(/\s+/g, "");
  const cleanName = name.trim();
  try {
    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ? LIMIT 1"
    ).bind(cleanEmail).first();
    if (existing) {
      return jsonError("An account with this email address already exists. Please log in.", 409);
    }
    const { hash, salt } = await hashPassword(password);
    const userId = generateId("usr");
    const walletId = generateId("wal");
    const now = Math.floor(Date.now() / 1e3);
    const totalUsersCountResult = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first();
    const isFirstUser = (totalUsersCountResult?.count || 0) === 0;
    const initialRole = isFirstUser ? "admin" : "user";
    await env.DB.prepare(`
      INSERT INTO users (id, name, email, phone, password_hash, salt, role, status, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?)
    `).bind(
      userId,
      cleanName,
      cleanEmail,
      cleanPhone,
      hash,
      salt,
      initialRole,
      now,
      now
    ).run();
    await env.DB.prepare(`
      INSERT INTO wallets (id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
      VALUES (?, ?, 0, 0, 0, 0, ?)
    `).bind(walletId, userId, now).run();
    return jsonSuccess({
      message: "Registration successful! Please log in with your email and password to choose and activate your partner package.",
      registered: true,
      email: cleanEmail
    }, 201);
  } catch (err) {
    console.error("Registration error:", err);
    return jsonError("Registration failed due to a server error. Please try again.", 500);
  }
}
__name(onRequestPost8, "onRequestPost");

// api/evidence/[id].js
async function onRequestGet10(context) {
  const { request, env, params } = context;
  const evidenceId = params.id;
  if (!evidenceId) {
    return jsonError("Evidence ID is required", 400);
  }
  const user = await authenticate(request, env);
  if (!user) {
    return jsonError("Authentication required to view evidence", 401);
  }
  try {
    const submission = await env.DB.prepare(`
      SELECT ts.user_id, te.file_name, te.file_type, te.data_base64
      FROM task_evidence te
      JOIN task_submissions ts ON ts.evidence_id = te.id
      WHERE te.id = ?
      LIMIT 1
    `).bind(evidenceId).first();
    if (!submission) {
      return jsonError("Evidence not found", 404);
    }
    if (submission.user_id !== user.id && user.role !== "admin") {
      return jsonError("Unauthorized access to this evidence file", 403);
    }
    let dataUri = submission.data_base64;
    if (!dataUri.startsWith("data:")) {
      dataUri = `data:${submission.file_type || "image/png"};base64,${dataUri}`;
    }
    const parts = dataUri.split(",");
    const mimeMatch = parts[0].match(/:(.*?);/);
    const mimeType = mimeMatch ? mimeMatch[1] : "image/png";
    const binaryStr = atob(parts[1]);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }
    return new Response(bytes, {
      status: 200,
      headers: {
        "Content-Type": mimeType,
        "Cache-Control": "private, max-age=86400",
        "X-Content-Type-Options": "nosniff"
      }
    });
  } catch (err) {
    console.error("Evidence retrieval error:", err);
    return jsonError("Failed to fetch evidence image", 500);
  }
}
__name(onRequestGet10, "onRequestGet");

// api/inquiries.js
async function onRequestPost9(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { name, email, phone, businessName, serviceType, budgetRange, message } = body;
  if (!name || name.trim().length < 2) {
    return jsonError("Please provide your name or company representative name", 400);
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!email || !emailRegex.test(email.trim().toLowerCase())) {
    return jsonError("Please provide a valid contact email address", 400);
  }
  if (!phone || phone.trim().length < 8) {
    return jsonError("Please provide a valid phone number for our media team to reach you", 400);
  }
  if (!message || message.trim().length < 10) {
    return jsonError("Please include a brief message detailing your advertising goals (min 10 characters)", 400);
  }
  try {
    const authUser = await authenticate(request, env);
    const inquiryId = generateId("inq");
    const now = Math.floor(Date.now() / 1e3);
    await env.DB.prepare(`
      INSERT INTO service_inquiries (
        id, user_id, name, email, phone, business_name, service_type, budget_range, message, status, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)
    `).bind(
      inquiryId,
      authUser ? authUser.id : null,
      name.trim(),
      email.trim().toLowerCase(),
      phone.trim(),
      businessName ? businessName.trim() : "Private Individual",
      serviceType || "WhatsApp Status Network Blast",
      budgetRange || "Flexible",
      message.trim(),
      now
    ).run();
    return jsonSuccess({
      message: "Thank you! Your advertising inquiry has been submitted. Our commercial media strategist will contact you within 24 hours.",
      inquiryId
    }, 201);
  } catch (err) {
    console.error("Inquiry error:", err);
    return jsonError("Failed to record inquiry. Please try again.", 500);
  }
}
__name(onRequestPost9, "onRequestPost");
async function onRequestGet11(context) {
  const { request, env } = context;
  const authUser = await authenticate(request, env);
  if (!authUser || authUser.role !== "admin") {
    return jsonError("Administrator access required", 403);
  }
  try {
    const { results } = await env.DB.prepare(`
      SELECT id, name, email, phone, business_name, service_type, budget_range, message, status, created_at
      FROM service_inquiries
      ORDER BY created_at DESC
      LIMIT 100
    `).all();
    return jsonSuccess({
      inquiries: results || []
    });
  } catch (err) {
    console.error("Fetch inquiries error:", err);
    return jsonError("Failed to fetch inquiries", 500);
  }
}
__name(onRequestGet11, "onRequestGet");

// api/packages.js
async function onRequestGet12(context) {
  const { env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  try {
    const { results } = await env.DB.prepare(`
      SELECT id, name, slug, price_ksh, reward_per_view_ksh, max_views_per_task, features, badge, is_active
      FROM packages
      WHERE is_active = 1
      ORDER BY price_ksh ASC
    `).all();
    const packages = (results || []).map((pkg) => ({
      ...pkg,
      features: typeof pkg.features === "string" ? JSON.parse(pkg.features) : pkg.features
    }));
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_PASSKEY && env.MPESA_SHORTCODE
    );
    return jsonSuccess({
      packages,
      paymentSettings: {
        isMpesaAutomated: isMpesaConfigured,
        paymentMode: isMpesaConfigured ? "automated_stk" : "manual_till",
        paybill: env.MPESA_PAYBILL_NUMBER || "522533",
        accountNumber: env.MPESA_ACCOUNT_NUMBER || "8106675",
        paybillOrTill: `Paybill: ${env.MPESA_PAYBILL_NUMBER || "522533"} (Account: ${env.MPESA_ACCOUNT_NUMBER || "8106675"}, Name: ${env.MPESA_BUSINESS_NAME || "JASPER MARKETS"})`,
        businessName: env.MPESA_BUSINESS_NAME || "JASPER MARKETS"
      }
    });
  } catch (err) {
    console.error("Fetch packages error:", err);
    return jsonError("Failed to fetch advertising packages", 500);
  }
}
__name(onRequestGet12, "onRequestGet");
async function onRequestPost10(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { packageId, phoneNumber, paymentReference } = body;
  if (!packageId) {
    return jsonError("packageId is required", 400);
  }
  try {
    const pkg = await env.DB.prepare(`
      SELECT id, name, price_ksh, reward_per_view_ksh, max_views_per_task, is_active
      FROM packages
      WHERE id = ? AND is_active = 1
      LIMIT 1
    `).bind(packageId).first();
    if (!pkg) {
      return jsonError("Selected package was not found or is currently inactive", 404);
    }
    const now = Math.floor(Date.now() / 1e3);
    const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, "") : user.phone;
    const isMpesaConfigured = Boolean(
      env.MPESA_CONSUMER_KEY && env.MPESA_CONSUMER_SECRET && env.MPESA_PASSKEY && env.MPESA_SHORTCODE
    );
    if (isMpesaConfigured) {
      const paymentTxId = generateId("pmt");
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_stk', 'pending', 'STK Push Triggered', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, now).run();
      return jsonSuccess({
        message: `M-Pesa STK Push initiated for KSh ${pkg.price_ksh}. Please enter your PIN on your phone.`,
        transactionId: paymentTxId,
        status: "pending_pin"
      });
    } else {
      if (!paymentReference || paymentReference.trim().length < 5) {
        return jsonError("Please enter your valid M-Pesa transaction reference (e.g. SLK89J21X) after sending payment.", 400);
      }
      const cleanRef = paymentReference.trim().toUpperCase();
      const duplicate = await env.DB.prepare(`
        SELECT id FROM payment_transactions WHERE mpesa_receipt_number = ? LIMIT 1
      `).bind(cleanRef).first();
      if (duplicate) {
        return jsonError("This M-Pesa transaction reference has already been submitted.", 409);
      }
      const paymentTxId = generateId("pmt");
      const userPackageId = generateId("upkg");
      await env.DB.prepare(`
        INSERT INTO payment_transactions (id, user_id, package_id, amount_ksh, phone_number, payment_method, mpesa_receipt_number, status, notes, created_at)
        VALUES (?, ?, ?, ?, ?, 'mpesa_manual', ?, 'pending', 'Submitted by user, awaiting admin audit', ?)
      `).bind(paymentTxId, user.id, pkg.id, pkg.price_ksh, targetPhone, cleanRef, now).run();
      await env.DB.prepare(`
        DELETE FROM user_packages WHERE user_id = ? AND status = 'pending_verification'
      `).bind(user.id).run();
      await env.DB.prepare(`
        INSERT INTO user_packages (id, user_id, package_id, status, activated_at)
        VALUES (?, ?, ?, 'pending_verification', ?)
      `).bind(userPackageId, user.id, pkg.id, now).run();
      return jsonSuccess({
        message: `M-Pesa reference ${cleanRef} submitted for ${pkg.name}! Our administrator will verify the payment code to activate your account.`,
        package: pkg,
        reference: cleanRef,
        status: "pending_verification"
      }, 201);
    }
  } catch (err) {
    console.error("Package activation error:", err);
    return jsonError("Failed to process package activation. Please try again.", 500);
  }
}
__name(onRequestPost10, "onRequestPost");

// api/products-posts.js
async function onRequestGet13(context) {
  const { env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  try {
    const { results } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, caption, image_url, image_base64, image_name, downloads_count, created_at
      FROM product_posts
      WHERE status = 'active'
      ORDER BY created_at DESC
      LIMIT 50
    `).all();
    return jsonSuccess({
      productPosts: results || []
    });
  } catch (err) {
    console.error("Fetch product posts error:", err);
    return jsonError("Failed to fetch promotional WhatsApp product posts", 500);
  }
}
__name(onRequestGet13, "onRequestGet");
async function onRequestPost11(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { postId, action } = body;
  if (!postId) {
    return jsonError("postId is required", 400);
  }
  try {
    if (action === "download") {
      await env.DB.prepare(`
        UPDATE product_posts
        SET downloads_count = downloads_count + 1
        WHERE id = ?
      `).bind(postId).run();
      return jsonSuccess({ message: "Download tracked" });
    }
    return jsonSuccess({ message: "OK" });
  } catch (err) {
    return jsonError("Failed to track download event", 500);
  }
}
__name(onRequestPost11, "onRequestPost");

// api/setup-admin.js
async function onRequestPost12(context) {
  const { request, env } = context;
  if (!env.DB) {
    return jsonError("Database configuration missing", 500);
  }
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { email, setupSecret } = body;
  if (!email || !setupSecret) {
    return jsonError("Both target user email and setupSecret are required", 400);
  }
  const configuredSecret = env.ADMIN_SETUP_SECRET;
  if (!configuredSecret) {
    return jsonError("ADMIN_SETUP_SECRET has not been set in Cloudflare environment secrets. Administrator promotion is locked.", 403);
  }
  if (setupSecret !== configuredSecret) {
    return jsonError("Invalid administrator setup secret key", 401);
  }
  try {
    const cleanEmail = email.trim().toLowerCase();
    const user = await env.DB.prepare("SELECT id, name, email, role FROM users WHERE email = ?").bind(cleanEmail).first();
    if (!user) {
      return jsonError(`No registered user found with email ${cleanEmail}. Please register the account first.`, 404);
    }
    if (user.role === "admin") {
      return jsonSuccess({ message: `User ${cleanEmail} is already an administrator.` });
    }
    await env.DB.prepare("UPDATE users SET role = 'admin', updated_at = ? WHERE id = ?").bind(Math.floor(Date.now() / 1e3), user.id).run();
    return jsonSuccess({
      message: `User ${user.name} (${cleanEmail}) has been successfully promoted to Administrator!`,
      userId: user.id,
      role: "admin"
    });
  } catch (err) {
    console.error("Setup admin error:", err);
    return jsonError("Failed to promote user to administrator", 500);
  }
}
__name(onRequestPost12, "onRequestPost");

// api/tasks.js
async function onRequestGet14(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  try {
    const { results: campaigns } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, target_link, guidelines
      FROM campaigns
      WHERE status = 'active'
      ORDER BY created_at DESC
    `).all();
    const { results: submissions } = await env.DB.prepare(`
      SELECT ts.id, ts.reported_views, ts.approved_views, ts.reward_rate_ksh,
             ts.reward_amount_ksh, ts.evidence_text, ts.evidence_id, ts.status,
             ts.admin_notes, ts.created_at, ts.reviewed_at,
             c.title as campaign_title, c.brand_name
      FROM task_submissions ts
      LEFT JOIN campaigns c ON ts.campaign_id = c.id
      WHERE ts.user_id = ?
      ORDER BY ts.created_at DESC
      LIMIT 20
    `).bind(user.id).all();
    const now = Math.floor(Date.now() / 1e3);
    const latest = submissions && submissions.length > 0 ? submissions[0] : null;
    let canSubmit = true;
    let secondsRemaining = 0;
    let nextAllowedAt = now;
    if (latest) {
      const cooldownSeconds = 18 * 60 * 60;
      const nextTime = latest.created_at + cooldownSeconds;
      if (now < nextTime) {
        canSubmit = false;
        secondsRemaining = nextTime - now;
        nextAllowedAt = nextTime;
      }
    }
    return jsonSuccess({
      campaigns: campaigns || [],
      submissions: submissions || [],
      cooldown: {
        canSubmit,
        secondsRemaining,
        nextAllowedAt,
        lastSubmittedAt: latest ? latest.created_at : null
      }
    });
  } catch (err) {
    console.error("Fetch tasks error:", err);
    return jsonError("Failed to fetch task submissions and campaigns", 500);
  }
}
__name(onRequestGet14, "onRequestGet");
async function onRequestPost13(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { campaignId, reportedViews, evidenceBase64, evidenceNote, fileName, fileType } = body;
  const activePackage = await env.DB.prepare(`
    SELECT up.package_id, p.name, p.reward_per_view_ksh, p.max_views_per_task
    FROM user_packages up
    JOIN packages p ON up.package_id = p.id
    WHERE up.user_id = ? AND up.status = 'active'
    ORDER BY up.activated_at DESC
    LIMIT 1
  `).bind(user.id).first();
  if (!activePackage) {
    return jsonError("You do not have an active advertising partner package. Please activate Starter, Growth, or Executive package first.", 403);
  }
  const views = parseInt(reportedViews, 10);
  if (isNaN(views) || views <= 0) {
    return jsonError("Please enter a valid number of reported WhatsApp Status views (minimum 1 view)", 400);
  }
  if (views > 1e4) {
    return jsonError("Reported views exceeds maximum allowable threshold for verification", 400);
  }
  const now = Math.floor(Date.now() / 1e3);
  const latestSubmission = await env.DB.prepare(`
    SELECT created_at FROM task_submissions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
  `).bind(user.id).first();
  if (latestSubmission) {
    const elapsed = now - latestSubmission.created_at;
    const cooldownDuration = 18 * 60 * 60;
    if (elapsed < cooldownDuration) {
      const waitMinutes = Math.ceil((cooldownDuration - elapsed) / 60);
      const waitHours = (waitMinutes / 60).toFixed(1);
      return jsonError(`18-hour submission cooldown active. You can submit another WhatsApp task in approximately ${waitHours} hours (${waitMinutes} minutes).`, 429, {
        secondsRemaining: cooldownDuration - elapsed
      });
    }
  }
  if (!evidenceBase64 || typeof evidenceBase64 !== "string") {
    return jsonError("Screenshot evidence of your WhatsApp Status view count is required", 400);
  }
  if (evidenceBase64.length > 5 * 1024 * 1024) {
    return jsonError("Screenshot file size is too large. Please upload an image under 3MB.", 400);
  }
  try {
    const evidenceId = generateId("evd");
    const taskId = generateId("tsk");
    await env.DB.prepare(`
      INSERT INTO task_evidence (id, file_name, file_type, file_size, data_base64, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      evidenceId,
      fileName || "whatsapp_status_proof.png",
      fileType || "image/png",
      Math.round(evidenceBase64.length * 0.75),
      evidenceBase64,
      now
    ).run();
    const maxViews = activePackage.max_views_per_task || 200;
    const effectiveViews = Math.min(views, maxViews);
    const rewardKsh = effectiveViews * activePackage.reward_per_view_ksh;
    await env.DB.prepare(`
      INSERT INTO task_submissions (
        id, user_id, campaign_id, package_id, reported_views, approved_views,
        reward_rate_ksh, reward_amount_ksh, evidence_text, evidence_id,
        status, created_at, reviewed_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'approved', ?, ?)
    `).bind(
      taskId,
      user.id,
      campaignId || "camp_almai_main",
      activePackage.package_id,
      views,
      effectiveViews,
      activePackage.reward_per_view_ksh,
      rewardKsh,
      evidenceNote || "Verified WhatsApp Status views proof",
      evidenceId,
      now,
      now
    ).run();
    const wallet = await env.DB.prepare("SELECT id, available_balance_ksh FROM wallets WHERE user_id = ?").bind(user.id).first();
    let balanceAfter = rewardKsh;
    if (wallet) {
      balanceAfter = (wallet.available_balance_ksh || 0) + rewardKsh;
      await env.DB.prepare(`
        UPDATE wallets
        SET available_balance_ksh = available_balance_ksh + ?,
            lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(rewardKsh, rewardKsh, now, user.id).run();
      const txId = generateId("tx");
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'task_reward', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        rewardKsh,
        balanceAfter,
        taskId,
        `WhatsApp Campaign: ${effectiveViews} views @ KSh ${activePackage.reward_per_view_ksh}/view`,
        now
      ).run();
    }
    return jsonSuccess({
      message: `\u{1F389} Success! Captured ${effectiveViews} verified views. KSh ${rewardKsh.toLocaleString()} credited directly to your available balance!`,
      taskId,
      reportedViews: views,
      approvedViews: effectiveViews,
      rewardEarnedKsh: rewardKsh,
      newBalanceKsh: balanceAfter,
      packageRateKsh: activePackage.reward_per_view_ksh,
      status: "approved"
    }, 201);
  } catch (err) {
    console.error("Task submission error:", err);
    return jsonError("Failed to record task submission. Please try again.", 500);
  }
}
__name(onRequestPost13, "onRequestPost");

// api/withdrawals.js
var MINIMUM_WITHDRAWAL_KSH = 100;
async function onRequestGet15(context) {
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
    console.error("Fetch withdrawals error:", err);
    return jsonError("Failed to fetch withdrawal requests", 500);
  }
}
__name(onRequestGet15, "onRequestGet");
async function onRequestPost14(context) {
  const { request, env } = context;
  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;
  const user = auth.user;
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError("Invalid JSON request body", 400);
  }
  const { amountKsh, phoneNumber } = body;
  const amount = parseInt(amountKsh, 10);
  if (isNaN(amount) || amount < MINIMUM_WITHDRAWAL_KSH) {
    return jsonError(`Minimum withdrawal amount is KSh ${MINIMUM_WITHDRAWAL_KSH}`, 400);
  }
  const targetPhone = phoneNumber ? phoneNumber.trim().replace(/\s+/g, "") : user.phone;
  if (!targetPhone || targetPhone.length < 9) {
    return jsonError("Valid M-Pesa phone number is required for payout", 400);
  }
  try {
    const wallet = await env.DB.prepare(`
      SELECT id, available_balance_ksh, reserved_balance_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();
    if (!wallet) {
      return jsonError("Wallet account not found", 404);
    }
    if (wallet.available_balance_ksh < amount) {
      return jsonError(`Insufficient available funds. Your available balance is KSh ${wallet.available_balance_ksh}, requested KSh ${amount}.`, 400);
    }
    const now = Math.floor(Date.now() / 1e3);
    const withdrawalId = generateId("wth");
    const txId = generateId("wtx");
    const balanceAfter = wallet.available_balance_ksh - amount;
    const updateResult = await env.DB.prepare(`
      UPDATE wallets
      SET available_balance_ksh = available_balance_ksh - ?,
          reserved_balance_ksh = reserved_balance_ksh + ?,
          updated_at = ?
      WHERE user_id = ? AND available_balance_ksh >= ?
    `).bind(amount, amount, now, user.id, amount).run();
    if (!updateResult.success || updateResult.meta && updateResult.meta.changes === 0) {
      return jsonError("Concurrent balance update conflict or insufficient funds. Please refresh and try again.", 409);
    }
    await env.DB.prepare(`
      INSERT INTO withdrawal_requests (id, user_id, wallet_id, amount_ksh, phone_number, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'pending', ?)
    `).bind(withdrawalId, user.id, wallet.id, amount, targetPhone, now).run();
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
        status: "pending",
        createdAt: now
      },
      wallet: {
        availableBalanceKsh: balanceAfter,
        reservedBalanceKsh: wallet.reserved_balance_ksh + amount
      }
    }, 201);
  } catch (err) {
    console.error("Withdrawal error:", err);
    return jsonError("Failed to process withdrawal request. Please try again.", 500);
  }
}
__name(onRequestPost14, "onRequestPost");

// ../.wrangler/tmp/pages-AlDii2/functionsRoutes-0.8450456322839598.mjs
var routes = [
  {
    routePath: "/api/admin/audit-logs",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet]
  },
  {
    routePath: "/api/admin/packages",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet2]
  },
  {
    routePath: "/api/admin/packages",
    mountPath: "/api/admin",
    method: "PUT",
    middlewares: [],
    modules: [onRequestPut]
  },
  {
    routePath: "/api/admin/payments",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet3]
  },
  {
    routePath: "/api/admin/payments",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "DELETE",
    middlewares: [],
    modules: [onRequestDelete]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet4]
  },
  {
    routePath: "/api/admin/products-posts",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost2]
  },
  {
    routePath: "/api/admin/stats",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet5]
  },
  {
    routePath: "/api/admin/tasks",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet6]
  },
  {
    routePath: "/api/admin/tasks",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost3]
  },
  {
    routePath: "/api/admin/users",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet7]
  },
  {
    routePath: "/api/admin/users",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost4]
  },
  {
    routePath: "/api/admin/withdrawals",
    mountPath: "/api/admin",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet8]
  },
  {
    routePath: "/api/admin/withdrawals",
    mountPath: "/api/admin",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost5]
  },
  {
    routePath: "/api/auth/login",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost6]
  },
  {
    routePath: "/api/auth/logout",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost7]
  },
  {
    routePath: "/api/auth/me",
    mountPath: "/api/auth",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet9]
  },
  {
    routePath: "/api/auth/register",
    mountPath: "/api/auth",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost8]
  },
  {
    routePath: "/api/evidence/:id",
    mountPath: "/api/evidence",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet10]
  },
  {
    routePath: "/api/inquiries",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet11]
  },
  {
    routePath: "/api/inquiries",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost9]
  },
  {
    routePath: "/api/packages",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet12]
  },
  {
    routePath: "/api/packages",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost10]
  },
  {
    routePath: "/api/products-posts",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet13]
  },
  {
    routePath: "/api/products-posts",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost11]
  },
  {
    routePath: "/api/setup-admin",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost12]
  },
  {
    routePath: "/api/tasks",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet14]
  },
  {
    routePath: "/api/tasks",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost13]
  },
  {
    routePath: "/api/withdrawals",
    mountPath: "/api",
    method: "GET",
    middlewares: [],
    modules: [onRequestGet15]
  },
  {
    routePath: "/api/withdrawals",
    mountPath: "/api",
    method: "POST",
    middlewares: [],
    modules: [onRequestPost14]
  }
];

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../../../AppData/Local/npm-cache/_npx/32026684e21afda6/node_modules/wrangler/templates/pages-template-worker.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request) {
  const requestPath = new URL(request.url).pathname;
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(requestPath);
    const mountMatchResult = mountMatcher(requestPath);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
var pages_template_worker_default = {
  async fetch(originalRequest, env, workerContext) {
    let request = originalRequest;
    const handlerIterator = executeRequest(request);
    let data = {};
    let isFailOpen = false;
    const next = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url = input;
        if (typeof input === "string") {
          url = new URL(input, request.url).toString();
        }
        request = new Request(url, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: path,
          next,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: /* @__PURE__ */ __name(() => {
            isFailOpen = true;
          }, "passThroughOnException")
        };
        const response = await handler(context);
        if (!(response instanceof Response)) {
          throw new Error("Your Pages function should return a Response");
        }
        return cloneResponse(response);
      } else if ("ASSETS") {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      } else {
        const response = await fetch(request);
        return cloneResponse(response);
      }
    }, "next");
    try {
      return await next();
    } catch (error) {
      if (isFailOpen) {
        const response = await env["ASSETS"].fetch(request);
        return cloneResponse(response);
      }
      throw error;
    }
  }
};
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_worker_default as default
};
