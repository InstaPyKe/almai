// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, DELETE /api/admin/audit-logs
// Protected Administrator Audit Log Inspection & Junk Log Clearing
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const { results } = await env.DB.prepare(`
      SELECT al.id, al.action, al.target_type, al.target_id, al.details, al.ip_address, al.created_at,
             u.name as admin_name, u.email as admin_email
      FROM admin_audit_logs al
      LEFT JOIN users u ON al.admin_id = u.id
      ORDER BY al.created_at DESC
      LIMIT 150
    `).all();

    const formatted = (results || []).map(row => ({
      ...row,
      details: row.details ? (typeof row.details === 'string' ? JSON.parse(row.details) : row.details) : null
    }));

    return jsonSuccess({
      auditLogs: formatted
    });

  } catch (err) {
    console.error('Audit logs fetch error:', err);
    return jsonError('Failed to fetch audit logs', 500);
  }
}

export async function onRequestDelete(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    const url = new URL(request.url);
    const clearAllParam = url.searchParams.get('clearAll') === 'true';
    let ids = [];
    let clearAll = clearAllParam;

    try {
      const text = await request.text();
      if (text && text.trim()) {
        const body = JSON.parse(text);
        if (Array.isArray(body?.ids)) ids = body.ids.filter(Boolean);
        if (body?.clearAll === true) clearAll = true;
      }
    } catch (e) {}

    if (clearAll) {
      const countRow = await env.DB.prepare('SELECT COUNT(*) as total FROM admin_audit_logs').first();
      const deletedCount = countRow?.total || 0;
      await env.DB.prepare('DELETE FROM admin_audit_logs').run();
      return jsonSuccess({
        message: `Cleared all ${deletedCount} system audit logs.`,
        deletedCount
      });
    }

    if (ids.length === 0) {
      return jsonError('Please select at least one audit log entry to clear', 400);
    }

    let deletedCount = 0;
    for (const logId of ids) {
      await env.DB.prepare('DELETE FROM admin_audit_logs WHERE id = ?').bind(logId).run();
      deletedCount++;
    }

    return jsonSuccess({
      message: `Cleared ${deletedCount} selected audit log entry(ies).`,
      deletedCount
    });
  } catch (err) {
    console.error('Audit logs delete error:', err);
    return jsonError('Failed to clear audit logs', 500);
  }
}
