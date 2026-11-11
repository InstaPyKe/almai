// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/cleanup
// Protected Administrator System Junk Inspection & Multi-Clear
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog } from '../_utils.js';

/**
 * GET /api/admin/cleanup
 * Returns live counts of stale/junk records across the system
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const now = Math.floor(Date.now() / 1000);

  try {
    const expiredSessions = await env.DB.prepare('SELECT COUNT(*) as c FROM sessions WHERE expires_at < ?').bind(now).first().catch(() => ({ c: 0 }));
    const failedPayments = await env.DB.prepare("SELECT COUNT(*) as c FROM payment_transactions WHERE status IN ('failed', 'rejected')").first().catch(() => ({ c: 0 }));
    const rejectedTasks = await env.DB.prepare("SELECT COUNT(*) as c FROM task_submissions WHERE status = 'rejected'").first().catch(() => ({ c: 0 }));
    const rejectedWithdrawals = await env.DB.prepare("SELECT COUNT(*) as c FROM withdrawal_requests WHERE status = 'rejected'").first().catch(() => ({ c: 0 }));
    const auditLogs = await env.DB.prepare('SELECT COUNT(*) as c FROM admin_audit_logs').first().catch(() => ({ c: 0 }));
    const orphanedEvidence = await env.DB.prepare(`
      SELECT COUNT(*) as c FROM task_evidence te
      WHERE NOT EXISTS (SELECT 1 FROM task_submissions ts WHERE ts.evidence_id = te.id)
    `).first().catch(() => ({ c: 0 }));
    const suspendedUsers = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'suspended' AND role != 'admin'").first().catch(() => ({ c: 0 }));

    return jsonSuccess({
      junkCounts: {
        expiredSessions: expiredSessions?.c || 0,
        failedPayments: failedPayments?.c || 0,
        rejectedTasks: rejectedTasks?.c || 0,
        rejectedWithdrawals: rejectedWithdrawals?.c || 0,
        auditLogs: auditLogs?.c || 0,
        orphanedEvidence: orphanedEvidence?.c || 0,
        suspendedUsers: suspendedUsers?.c || 0
      }
    });
  } catch (err) {
    console.error('Cleanup counts error:', err);
    return jsonError('Failed to inspect junk system counts', 500);
  }
}

/**
 * POST /api/admin/cleanup
 * Multi-clear selected junk system data categories or selected record IDs
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

  const targets = Array.isArray(body.targets) ? body.targets : [];
  const paymentIds = Array.isArray(body.paymentIds) ? body.paymentIds.filter(Boolean) : [];
  const taskIds = Array.isArray(body.taskIds) ? body.taskIds.filter(Boolean) : [];
  const withdrawalIds = Array.isArray(body.withdrawalIds) ? body.withdrawalIds.filter(Boolean) : [];

  if (targets.length === 0 && paymentIds.length === 0 && taskIds.length === 0 && withdrawalIds.length === 0) {
    return jsonError('Please select at least one junk category or record to clear', 400);
  }

  const now = Math.floor(Date.now() / 1000);
  const ip = request.headers.get('cf-connecting-ip') || '';
  const breakdown = {};
  let totalDeleted = 0;

  try {
    // 1. Expired sessions
    if (targets.includes('expired_sessions')) {
      const res = await env.DB.prepare('DELETE FROM sessions WHERE expires_at < ?').bind(now).run();
      const count = res?.meta?.changes || 0;
      breakdown.expiredSessions = count;
      totalDeleted += count;
    }

    // 2. Failed / rejected payment codes
    if (targets.includes('failed_payments')) {
      const res = await env.DB.prepare("DELETE FROM payment_transactions WHERE status IN ('failed', 'rejected')").run();
      const count = res?.meta?.changes || 0;
      breakdown.failedPayments = count;
      totalDeleted += count;
    }

    // 3. Rejected task submissions
    if (targets.includes('rejected_tasks')) {
      const res = await env.DB.prepare("DELETE FROM task_submissions WHERE status = 'rejected'").run();
      const count = res?.meta?.changes || 0;
      breakdown.rejectedTasks = count;
      totalDeleted += count;
    }

    // 4. Orphaned screenshot evidence blobs
    if (targets.includes('orphaned_evidence')) {
      const res = await env.DB.prepare(`
        DELETE FROM task_evidence
        WHERE NOT EXISTS (SELECT 1 FROM task_submissions ts WHERE ts.evidence_id = task_evidence.id)
      `).run();
      const count = res?.meta?.changes || 0;
      breakdown.orphanedEvidence = count;
      totalDeleted += count;
    }

    // 5. Rejected withdrawal requests
    if (targets.includes('rejected_withdrawals')) {
      const res = await env.DB.prepare("DELETE FROM withdrawal_requests WHERE status = 'rejected'").run();
      const count = res?.meta?.changes || 0;
      breakdown.rejectedWithdrawals = count;
      totalDeleted += count;
    }

    // 6. All audit logs or old audit logs (>7 days)
    if (targets.includes('all_audit_logs')) {
      const res = await env.DB.prepare('DELETE FROM admin_audit_logs').run();
      const count = res?.meta?.changes || 0;
      breakdown.auditLogs = count;
      totalDeleted += count;
    } else if (targets.includes('old_audit_logs')) {
      const sevenDaysAgo = now - 7 * 86400;
      const res = await env.DB.prepare('DELETE FROM admin_audit_logs WHERE created_at < ?').bind(sevenDaysAgo).run();
      const count = res?.meta?.changes || 0;
      breakdown.oldAuditLogs = count;
      totalDeleted += count;
    }

    // 7. Specific selected payment IDs
    if (paymentIds.length > 0) {
      let c = 0;
      for (const id of paymentIds) {
        const res = await env.DB.prepare('DELETE FROM payment_transactions WHERE id = ?').bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedPayments = c;
      totalDeleted += c;
    }

    // 8. Specific selected task IDs
    if (taskIds.length > 0) {
      let c = 0;
      for (const id of taskIds) {
        const res = await env.DB.prepare('DELETE FROM task_submissions WHERE id = ?').bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedTasks = c;
      totalDeleted += c;
    }

    // 9. Specific selected withdrawal IDs (only non-pending or rejected/completed to protect reserved funds)
    if (withdrawalIds.length > 0) {
      let c = 0;
      for (const id of withdrawalIds) {
        const res = await env.DB.prepare("DELETE FROM withdrawal_requests WHERE id = ? AND status != 'pending'").bind(id).run();
        c += res?.meta?.changes || 0;
      }
      breakdown.selectedWithdrawals = c;
      totalDeleted += c;
    }

    // Log the cleanup unless all audit logs were explicitly wiped without keeping trace
    if (!targets.includes('all_audit_logs')) {
      await createAuditLog(env, {
        adminId: admin.id,
        action: 'SYSTEM_JUNK_CLEANUP',
        targetType: 'system',
        targetId: 'cleanup',
        details: { targets, breakdown, totalDeleted },
        ip
      });
    }

    return jsonSuccess({
      message: `System cleanup complete: cleared ${totalDeleted} junk record(s).`,
      totalDeleted,
      breakdown
    });
  } catch (err) {
    console.error('System cleanup error:', err);
    return jsonError('Failed to execute system junk cleanup', 500);
  }
}

