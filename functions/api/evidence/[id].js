// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET /api/evidence/[id]
// ====================================================================

import { jsonError, authenticate } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env, params } = context;

  const evidenceId = params.id;
  if (!evidenceId) {
    return jsonError('Evidence ID is required', 400);
  }

  const user = await authenticate(request, env);
  if (!user) {
    return jsonError('Authentication required to view evidence', 401);
  }

  try {
    // Check ownership or admin status
    const submission = await env.DB.prepare(`
      SELECT ts.user_id, te.file_name, te.file_type, te.data_base64
      FROM task_evidence te
      JOIN task_submissions ts ON ts.evidence_id = te.id
      WHERE te.id = ?
      LIMIT 1
    `).bind(evidenceId).first();

    if (!submission) {
      return jsonError('Evidence not found', 404);
    }

    if (submission.user_id !== user.id && user.role !== 'admin') {
      return jsonError('Unauthorized access to this evidence file', 403);
    }

    let dataUri = submission.data_base64;
    // Check if it's already a full data URL
    if (!dataUri.startsWith('data:')) {
      dataUri = `data:${submission.file_type || 'image/png'};base64,${dataUri}`;
    }

    // Convert data URI to raw binary bytes for direct image response
    const parts = dataUri.split(',');
    const mimeMatch = parts[0].match(/:(.*?);/);
    const mimeType = mimeMatch ? mimeMatch[1] : 'image/png';
    const binaryStr = atob(parts[1]);
    const len = binaryStr.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
      bytes[i] = binaryStr.charCodeAt(i);
    }

    return new Response(bytes, {
      status: 200,
      headers: {
        'Content-Type': mimeType,
        'Cache-Control': 'private, max-age=86400',
        'X-Content-Type-Options': 'nosniff'
      }
    });

  } catch (err) {
    console.error('Evidence retrieval error:', err);
    return jsonError('Failed to fetch evidence image', 500);
  }
}
