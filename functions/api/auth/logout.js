// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: POST /api/auth/logout
// ====================================================================

import { jsonSuccess, getSessionToken } from '../_utils.js';

export async function onRequestPost(context) {
  const { request, env } = context;

  const token = getSessionToken(request);

  if (token && env.DB) {
    try {
      await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(token).run();
    } catch (err) {
      console.error('Logout session delete error:', err);
    }
  }

  // Clear cookie
  const isHttps = request.url.startsWith('https://');
  const clearCookieHeader = `almai_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${isHttps ? '; Secure' : ''}`;

  return jsonSuccess({
    message: 'Signed out successfully'
  }, 200, {
    'Set-Cookie': clearCookieHeader
  });
}
