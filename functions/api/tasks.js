// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/tasks
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, generateId } from './_utils.js';

/**
 * GET /api/tasks
 * Fetch available campaign guidelines, user submission history, and 24h cooldown timer
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  try {
    // 1. Fetch active campaigns
    const { results: campaigns } = await env.DB.prepare(`
      SELECT id, title, brand_name, description, target_link, guidelines
      FROM campaigns
      WHERE status = 'active'
      ORDER BY created_at DESC
    `).all();

    // 2. Fetch user recent submissions (limit 20)
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

    // 3. Cooldown calculation (18 hours)
    const now = Math.floor(Date.now() / 1000);
    const latest = submissions && submissions.length > 0 ? submissions[0] : null;

    let canSubmit = true;
    let secondsRemaining = 0;
    let nextAllowedAt = now;

    if (latest) {
      const cooldownSeconds = 18 * 60 * 60; // 18 hours
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
    console.error('Fetch tasks error:', err);
    return jsonError('Failed to fetch task submissions and campaigns', 500);
  }
}

/**
 * POST /api/tasks
 * Submit WhatsApp Status evidence and automatically calculate verified balance
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

  const { campaignId, reportedViews, evidenceBase64, evidenceNote, fileName, fileType } = body;

  // 1. Verify active package
  const activePackage = await env.DB.prepare(`
    SELECT up.package_id, p.name, p.reward_per_view_ksh, p.max_views_per_task
    FROM user_packages up
    JOIN packages p ON up.package_id = p.id
    WHERE up.user_id = ? AND up.status = 'active'
    ORDER BY up.activated_at DESC
    LIMIT 1
  `).bind(user.id).first();

  if (!activePackage) {
    return jsonError('You do not have an active advertising partner package. Please activate Starter, Growth, or Executive package first.', 403);
  }

  // 2. Validate views
  const views = parseInt(reportedViews, 10);
  if (isNaN(views) || views <= 0) {
    return jsonError('Please enter a valid number of reported WhatsApp Status views (minimum 1 view)', 400);
  }

  if (views > 10000) {
    return jsonError('Reported views exceeds maximum allowable threshold for verification', 400);
  }

  // 3. Enforce 18-hour Cooldown on server
  const now = Math.floor(Date.now() / 1000);
  const latestSubmission = await env.DB.prepare(`
    SELECT created_at FROM task_submissions WHERE user_id = ? ORDER BY created_at DESC LIMIT 1
  `).bind(user.id).first();

  if (latestSubmission) {
    const elapsed = now - latestSubmission.created_at;
    const cooldownDuration = 18 * 60 * 60; // 18 hours
    if (elapsed < cooldownDuration) {
      const waitMinutes = Math.ceil((cooldownDuration - elapsed) / 60);
      const waitHours = (waitMinutes / 60).toFixed(1);
      return jsonError(`18-hour submission cooldown active. You can submit another WhatsApp task in approximately ${waitHours} hours (${waitMinutes} minutes).`, 429, {
        secondsRemaining: cooldownDuration - elapsed
      });
    }
  }

  // 4. Validate evidence screenshot
  if (!evidenceBase64 || typeof evidenceBase64 !== 'string') {
    return jsonError('Screenshot evidence of your WhatsApp Status view count is required', 400);
  }

  // Check payload size (limit max 3.5MB base64)
  if (evidenceBase64.length > 5 * 1024 * 1024) {
    return jsonError('Screenshot file size is too large. Please upload an image under 3MB.', 400);
  }

  try {
    const evidenceId = generateId('evd');
    const taskId = generateId('tsk');

    // 5. Store evidence
    await env.DB.prepare(`
      INSERT INTO task_evidence (id, file_name, file_type, file_size, data_base64, created_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      evidenceId,
      fileName || 'whatsapp_status_proof.png',
      fileType || 'image/png',
      Math.round(evidenceBase64.length * 0.75),
      evidenceBase64,
      now
    ).run();

    // 6. Record submission in 'pending' status awaiting administrator verification
    const maxViews = activePackage.max_views_per_task || 200;
    const cappedViews = Math.min(views, maxViews);
    const estimatedRewardKsh = cappedViews * activePackage.reward_per_view_ksh;

    await env.DB.prepare(`
      INSERT INTO task_submissions (
        id, user_id, campaign_id, package_id, reported_views, approved_views,
        reward_rate_ksh, reward_amount_ksh, evidence_text, evidence_id,
        status, created_at, reviewed_at
      )
      VALUES (?, ?, ?, ?, ?, 0, ?, 0, ?, ?, 'pending', ?, NULL)
    `).bind(
      taskId,
      user.id,
      campaignId || 'camp_almai_main',
      activePackage.package_id,
      views,
      activePackage.reward_per_view_ksh,
      evidenceNote || 'WhatsApp Status views proof submitted',
      evidenceId,
      now
    ).run();

    return jsonSuccess({
      message: `Task submitted successfully! Your submission of ${views} WhatsApp views is awaiting administrator approval. Your wallet balance will be updated once approved by an administrator.`,
      taskId,
      reportedViews: views,
      estimatedRewardKsh,
      packageRateKsh: activePackage.reward_per_view_ksh,
      status: 'pending'
    }, 201);

  } catch (err) {
    console.error('Task submission error:', err);
    return jsonError('Failed to record task submission. Please try again.', 500);
  }
}
