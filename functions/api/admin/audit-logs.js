// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/admin/audit-logs
// Protected Administrator Audit Log Inspection
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
      JOIN users u ON al.admin_id = u.id
      ORDER BY al.created_at DESC
      LIMIT 100
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
