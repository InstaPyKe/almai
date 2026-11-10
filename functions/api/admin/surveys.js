// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/surveys
// Protected Administrator Surveys Manager
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    // 1. Fetch all surveys with metrics
    const { results: surveys } = await env.DB.prepare(`
      SELECT s.*,
        (SELECT COUNT(*) FROM survey_responses sr WHERE sr.survey_id = s.id) as response_count,
        (SELECT COALESCE(SUM(reward_amount_ksh), 0) FROM survey_responses sr WHERE sr.survey_id = s.id) as total_payout_ksh
      FROM surveys s
      ORDER BY s.created_at DESC
    `).all();

    // 2. Fetch overall stats
    const statsRow = await env.DB.prepare(`
      SELECT 
        COUNT(*) as total_surveys,
        COALESCE(SUM(completions_count), 0) as total_completions,
        (SELECT COUNT(*) FROM survey_responses) as verified_responses,
        (SELECT COALESCE(SUM(reward_amount_ksh), 0) FROM survey_responses) as total_paid_ksh
      FROM surveys
    `).first().catch(() => null);

    const formattedSurveys = (surveys || []).map(s => {
      let questions = [];
      try {
        questions = JSON.parse(s.questions);
      } catch (e) {
        questions = [];
      }

      return {
        ...s,
        questionsCount: questions.length,
        questions
      };
    });

    return jsonSuccess({
      surveys: formattedSurveys,
      stats: {
        totalSurveys: statsRow?.total_surveys || 0,
        totalCompletions: statsRow?.total_completions || 0,
        verifiedResponses: statsRow?.verified_responses || 0,
        totalPaidKsh: statsRow?.total_paid_ksh || 0
      }
    });

  } catch (err) {
    console.error('Admin fetch surveys error:', err);
    return jsonError('Failed to fetch admin surveys', 500);
  }
}

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

  const { action } = body;

  const now = Math.floor(Date.now() / 1000);
  const ip = request.headers.get('cf-connecting-ip') || '';

  try {
    if (action === 'create') {
      const { title, category, description, rewardKsh, estimatedMinutes, questions, maxCompletions, targetPackageId } = body;

      if (!title || !title.trim()) {
        return jsonError('Survey title is required', 400);
      }

      if (!description || !description.trim()) {
        return jsonError('Survey description is required', 400);
      }

      const reward = parseInt(rewardKsh, 10);
      if (isNaN(reward) || reward < 10) {
        return jsonError('Reward must be at least KSh 10 per completion', 400);
      }

      const estMins = parseInt(estimatedMinutes, 10) || 3;
      const maxComp = parseInt(maxCompletions, 10) || 5000;

      // Validate questions array
      if (!Array.isArray(questions) || questions.length === 0) {
        return jsonError('Please provide at least one survey question', 400);
      }

      const cleanedQuestions = [];
      for (let i = 0; i < questions.length; i++) {
        const q = questions[i];
        if (!q.text || !q.text.trim()) {
          return jsonError(`Question #${i + 1} text is required`, 400);
        }
        if (!Array.isArray(q.options) || q.options.length < 2) {
          return jsonError(`Question #${i + 1} must have at least 2 choices / options`, 400);
        }
        cleanedQuestions.push({
          id: q.id || `q${i + 1}`,
          text: q.text.trim(),
          options: q.options.map(opt => String(opt).trim()).filter(Boolean)
        });
      }

      const surveyId = generateId('srv');

      await env.DB.prepare(`
        INSERT INTO surveys (id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)
      `).bind(
        surveyId,
        title.trim(),
        (category || 'Consumer Habits').trim(),
        description.trim(),
        reward,
        estMins,
        JSON.stringify(cleanedQuestions),
        targetPackageId || null,
        maxComp,
        now
      ).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'CREATE_SURVEY',
        targetType: 'survey',
        targetId: surveyId,
        details: { title, rewardKsh: reward, questionsCount: cleanedQuestions.length },
        ip
      });

      return jsonSuccess({
        message: `Paid survey "${title}" created successfully with reward KSh ${reward}!`,
        surveyId
      }, 201);

    } else if (action === 'toggle') {
      const { surveyId } = body;
      if (!surveyId) return jsonError('surveyId is required', 400);

      const existing = await env.DB.prepare('SELECT id, title, is_active FROM surveys WHERE id = ?').bind(surveyId).first();
      if (!existing) return jsonError('Survey not found', 404);

      const newStatus = existing.is_active ? 0 : 1;
      await env.DB.prepare('UPDATE surveys SET is_active = ? WHERE id = ?').bind(newStatus, surveyId).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: newStatus ? 'ACTIVATE_SURVEY' : 'PAUSE_SURVEY',
        targetType: 'survey',
        targetId: surveyId,
        details: { title: existing.title, is_active: newStatus },
        ip
      });

      return jsonSuccess({
        message: `Survey status updated to ${newStatus ? 'Active' : 'Paused'}.`,
        isActive: newStatus
      });

    } else if (action === 'delete') {
      const { surveyId } = body;
      if (!surveyId) return jsonError('surveyId is required', 400);

      const existing = await env.DB.prepare('SELECT id, title FROM surveys WHERE id = ?').bind(surveyId).first();
      if (!existing) return jsonError('Survey not found', 404);

      await env.DB.prepare('DELETE FROM surveys WHERE id = ?').bind(surveyId).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'DELETE_SURVEY',
        targetType: 'survey',
        targetId: surveyId,
        details: { title: existing.title },
        ip
      });

      return jsonSuccess({
        message: `Survey "${existing.title}" deleted.`
      });

    } else {
      return jsonError(`Unsupported survey action: ${action}`, 400);
    }

  } catch (err) {
    console.error('Admin survey action error:', err);
    return jsonError('Failed to execute survey action', 500);
  }
}

