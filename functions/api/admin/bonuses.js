// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/admin/bonuses
// Regulated Active User Bonus Policy & Batch Rewards Distribution
// ====================================================================

import { jsonError, jsonSuccess, requireAdmin, createAuditLog, generateId } from '../_utils.js';

const VALID_BALANCE_TYPES = ['views', 'referrals', 'surveys'];

/**
 * Ensure bonus regulation & distribution tables exist and default policy is seeded.
 */
async function ensureBonusTables(db) {
  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_regulations (
      id TEXT PRIMARY KEY,
      is_enabled INTEGER NOT NULL DEFAULT 1,
      min_bonus_ksh INTEGER NOT NULL DEFAULT 10,
      max_bonus_per_user_ksh INTEGER NOT NULL DEFAULT 5000,
      daily_budget_cap_ksh INTEGER NOT NULL DEFAULT 100000,
      cooldown_hours INTEGER NOT NULL DEFAULT 24,
      require_active_package INTEGER NOT NULL DEFAULT 1,
      default_balance_type TEXT NOT NULL DEFAULT 'views',
      updated_by TEXT,
      updated_at INTEGER NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_distributions (
      id TEXT PRIMARY KEY,
      campaign_title TEXT NOT NULL,
      amount_per_user_ksh INTEGER NOT NULL,
      recipient_count INTEGER NOT NULL DEFAULT 0,
      total_disbursed_ksh INTEGER NOT NULL DEFAULT 0,
      balance_type TEXT NOT NULL DEFAULT 'views',
      eligibility_scope TEXT NOT NULL DEFAULT 'active_paid',
      package_filter_id TEXT,
      min_approved_views INTEGER NOT NULL DEFAULT 0,
      admin_id TEXT,
      created_at INTEGER NOT NULL
    )
  `).run();

  await db.prepare(`
    CREATE TABLE IF NOT EXISTS bonus_recipient_logs (
      id TEXT PRIMARY KEY,
      distribution_id TEXT NOT NULL,
      user_id TEXT NOT NULL,
      amount_ksh INTEGER NOT NULL,
      balance_type TEXT NOT NULL DEFAULT 'views',
      created_at INTEGER NOT NULL
    )
  `).run();

  await db.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => {});

  const now = Math.floor(Date.now() / 1000);
  await db.prepare(`
    INSERT OR IGNORE INTO bonus_regulations (
      id, is_enabled, min_bonus_ksh, max_bonus_per_user_ksh, daily_budget_cap_ksh,
      cooldown_hours, require_active_package, default_balance_type, updated_by, updated_at
    ) VALUES ('default', 1, 10, 5000, 100000, 24, 1, 'views', 'system', ?)
  `).bind(now).run();
}

async function getRegulationsAndBudget(db) {
  const regulations = await db.prepare("SELECT * FROM bonus_regulations WHERE id = 'default' LIMIT 1").first();
  const now = Math.floor(Date.now() / 1000);
  const since24h = now - 86400;

  const dailyRow = await db.prepare(`
    SELECT COALESCE(SUM(total_disbursed_ksh), 0) as disbursed_24h
    FROM bonus_distributions
    WHERE created_at >= ?
  `).bind(since24h).first();

  const allTimeRow = await db.prepare(`
    SELECT
      COALESCE(SUM(total_disbursed_ksh), 0) as total_disbursed,
      COALESCE(SUM(recipient_count), 0) as total_recipients
    FROM bonus_distributions
  `).first();

  const todayDisbursedKsh = dailyRow?.disbursed_24h || 0;
  const dailyBudgetCapKsh = regulations?.daily_budget_cap_ksh || 100000;

  return {
    regulations,
    budgetStats: {
      todayDisbursedKsh,
      dailyBudgetCapKsh,
      remainingDailyBudgetKsh: Math.max(0, dailyBudgetCapKsh - todayDisbursedKsh),
      totalAllTimeBonusKsh: allTimeRow?.total_disbursed || 0,
      totalBonusRecipientsCount: allTimeRow?.total_recipients || 0
    }
  };
}

/**
 * Resolve eligible active users matching scope, package filter, approved views floor & cooldown regulation.
 */
async function resolveEligibleActiveUsers(db, regulations, params) {
  const scope = params.scope || 'active_paid';
  const packageId = (params.packageId && params.packageId !== 'all') ? String(params.packageId).trim() : '';
  const minApprovedViews = Math.max(0, parseInt(params.minApprovedViews, 10) || 0);
  const selectedIds = Array.isArray(params.userIds) ? params.userIds.filter(Boolean) : [];

  let blockedReason = null;
  if (scope === 'all_active' && regulations.require_active_package === 1) {
    blockedReason = 'Current Bonus Regulation requires an Active Paid Package. Either target "Active Paid Partners" or disable "Require Active Package" in Regulations first.';
  }

  // Pull active non-admin users along with active package and approved views count
  const { results: candidateRows } = await db.prepare(`
    SELECT
      u.id,
      u.name,
      u.email,
      u.phone,
      (
        SELECT up.package_id
        FROM user_packages up
        WHERE up.user_id = u.id AND up.status = 'active'
        ORDER BY up.activated_at DESC
        LIMIT 1
      ) as active_package_id,
      (
        SELECT p.name
        FROM user_packages up
        JOIN packages p ON up.package_id = p.id
        WHERE up.user_id = u.id AND up.status = 'active'
        ORDER BY up.activated_at DESC
        LIMIT 1
      ) as active_package_name,
      COALESCE((
        SELECT SUM(CASE WHEN ts.status = 'approved' THEN ts.approved_views ELSE 0 END)
        FROM task_submissions ts
        WHERE ts.user_id = u.id
      ), 0) as total_approved_views
    FROM users u
    WHERE u.status = 'active' AND u.role != 'admin'
  `).all();

  const candidates = (candidateRows || []).filter(u => {
    if (scope === 'selected') {
      if (!selectedIds.includes(u.id)) return false;
      if (regulations.require_active_package === 1 && !u.active_package_id) return false;
    } else if (scope === 'active_paid') {
      if (!u.active_package_id) return false;
    }
    if (packageId && u.active_package_id !== packageId) return false;
    if ((u.total_approved_views || 0) < minApprovedViews) return false;
    return true;
  });

  // Cooldown enforcement check against bonus_recipient_logs
  const cooldownHours = Math.max(0, Number(regulations.cooldown_hours || 0));
  const now = Math.floor(Date.now() / 1000);
  const cooldownCutoff = now - cooldownHours * 3600;

  let recentlyRewardedSet = new Set();
  if (cooldownHours > 0 && candidates.length > 0) {
    const { results: recentLogs } = await db.prepare(`
      SELECT DISTINCT user_id
      FROM bonus_recipient_logs
      WHERE created_at >= ?
    `).bind(cooldownCutoff).all();
    for (const r of (recentLogs || [])) {
      recentlyRewardedSet.add(r.user_id);
    }
  }

  const eligibleUsers = [];
  let cooldownSkippedCount = 0;

  for (const u of candidates) {
    if (cooldownHours > 0 && recentlyRewardedSet.has(u.id)) {
      cooldownSkippedCount++;
    } else {
      eligibleUsers.push(u);
    }
  }

  return {
    eligibleUsers,
    matchedBeforeCooldown: candidates.length,
    cooldownSkippedCount,
    blockedReason
  };
}

/**
 * GET /api/admin/bonuses
 * Returns active bonus regulations, daily budget stats, active user counts & recent batch history.
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  try {
    await ensureBonusTables(env.DB);
    const { regulations, budgetStats } = await getRegulationsAndBudget(env.DB);

    const activeRegRow = await env.DB.prepare("SELECT COUNT(*) as c FROM users WHERE status = 'active' AND role != 'admin'").first();
    const activePaidRow = await env.DB.prepare(`
      SELECT COUNT(DISTINCT u.id) as c
      FROM users u
      JOIN user_packages up ON up.user_id = u.id
      WHERE u.status = 'active' AND u.role != 'admin' AND up.status = 'active'
    `).first();

    const { results: packages } = await env.DB.prepare('SELECT id, name, slug FROM packages ORDER BY price_ksh ASC').all();

    const { results: recentDistributions } = await env.DB.prepare(`
      SELECT
        bd.id, bd.campaign_title, bd.amount_per_user_ksh, bd.recipient_count,
        bd.total_disbursed_ksh, bd.balance_type, bd.eligibility_scope,
        bd.package_filter_id, bd.min_approved_views, bd.created_at,
        u.name as admin_name
      FROM bonus_distributions bd
      LEFT JOIN users u ON bd.admin_id = u.id
      ORDER BY bd.created_at DESC
      LIMIT 20
    `).all();

    return jsonSuccess({
      regulations,
      budgetStats,
      activeSummary: {
        activeRegisteredCount: activeRegRow?.c || 0,
        activePaidCount: activePaidRow?.c || 0
      },
      packages: packages || [],
      recentDistributions: recentDistributions || []
    });
  } catch (err) {
    console.error('Admin bonuses GET error:', err);
    return jsonError('Failed to load active user bonus configuration', 500);
  }
}

/**
 * POST /api/admin/bonuses
 * Supports: save_regulations | preview | distribute
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  const auth = await requireAdmin(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const admin = auth.user;
  const ip = request.headers.get('cf-connecting-ip') || '';

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonError('Invalid JSON request body', 400);
  }

  const action = body.action || 'distribute';

  try {
    await ensureBonusTables(env.DB);
    const now = Math.floor(Date.now() / 1000);

    // ------------------------------------------------------------------
    // 1. UPDATE / SAVE BONUS REGULATIONS POLICY
    // ------------------------------------------------------------------
    if (action === 'save_regulations') {
      const isEnabled = body.isEnabled === false || body.isEnabled === 0 ? 0 : 1;
      const minBonusKsh = parseInt(body.minBonusKsh, 10);
      const maxBonusPerUserKsh = parseInt(body.maxBonusPerUserKsh, 10);
      const dailyBudgetCapKsh = parseInt(body.dailyBudgetCapKsh, 10);
      const cooldownHours = parseInt(body.cooldownHours, 10);
      const requireActivePackage = body.requireActivePackage === false || body.requireActivePackage === 0 ? 0 : 1;
      const defaultBalanceType = VALID_BALANCE_TYPES.includes(body.defaultBalanceType) ? body.defaultBalanceType : 'views';

      if (isNaN(minBonusKsh) || minBonusKsh < 1) {
        return jsonError('Minimum bonus must be at least KSh 1', 400);
      }
      if (isNaN(maxBonusPerUserKsh) || maxBonusPerUserKsh < minBonusKsh) {
        return jsonError('Maximum bonus per user must be greater than or equal to minimum bonus', 400);
      }
      if (isNaN(dailyBudgetCapKsh) || dailyBudgetCapKsh < maxBonusPerUserKsh) {
        return jsonError('Daily budget cap must be at least the maximum single user bonus', 400);
      }
      if (isNaN(cooldownHours) || cooldownHours < 0 || cooldownHours > 8760) {
        return jsonError('Cooldown hours must be between 0 and 8,760 hours (1 year)', 400);
      }

      await env.DB.prepare(`
        UPDATE bonus_regulations
        SET is_enabled = ?,
            min_bonus_ksh = ?,
            max_bonus_per_user_ksh = ?,
            daily_budget_cap_ksh = ?,
            cooldown_hours = ?,
            require_active_package = ?,
            default_balance_type = ?,
            updated_by = ?,
            updated_at = ?
        WHERE id = 'default'
      `).bind(
        isEnabled,
        minBonusKsh,
        maxBonusPerUserKsh,
        dailyBudgetCapKsh,
        cooldownHours,
        requireActivePackage,
        defaultBalanceType,
        admin.id,
        now
      ).run();

      await createAuditLog(env, {
        adminId: admin.id,
        action: 'UPDATE_BONUS_REGULATIONS',
        targetType: 'bonus_regulations',
        targetId: 'default',
        details: {
          isEnabled,
          minBonusKsh,
          maxBonusPerUserKsh,
          dailyBudgetCapKsh,
          cooldownHours,
          requireActivePackage,
          defaultBalanceType
        },
        ip
      });

      const refreshed = await getRegulationsAndBudget(env.DB);
      return jsonSuccess({
        message: 'Bonus regulation policy saved successfully.',
        ...refreshed
      });
    }

    // ------------------------------------------------------------------
    // 2. PREVIEW ELIGIBLE ACTIVE RECIPIENTS & REGULATION VALIDATION
    // ------------------------------------------------------------------
    const { regulations, budgetStats } = await getRegulationsAndBudget(env.DB);
    const amountPerUserKsh = parseInt(body.amountPerUserKsh ?? body.amountKsh, 10) || 0;
    const scope = body.scope || 'active_paid';
    const balanceType = VALID_BALANCE_TYPES.includes(body.balanceType)
      ? body.balanceType
      : (regulations.default_balance_type || 'views');

    const { eligibleUsers, matchedBeforeCooldown, cooldownSkippedCount, blockedReason } =
      await resolveEligibleActiveUsers(env.DB, regulations, {
        scope,
        packageId: body.packageId,
        minApprovedViews: body.minApprovedViews,
        userIds: body.userIds
      });

    const totalDisbursedKsh = Math.max(0, amountPerUserKsh) * eligibleUsers.length;

    let regulationViolation = blockedReason;
    if (!regulationViolation && regulations.is_enabled !== 1) {
      regulationViolation = 'Active User Bonus payouts are currently paused by admin regulation settings.';
    } else if (!regulationViolation && (amountPerUserKsh < regulations.min_bonus_ksh || amountPerUserKsh > regulations.max_bonus_per_user_ksh)) {
      regulationViolation = `Specified bonus (KSh ${amountPerUserKsh.toLocaleString()}) violates admin regulation range: KSh ${regulations.min_bonus_ksh.toLocaleString()} – KSh ${regulations.max_bonus_per_user_ksh.toLocaleString()}.`;
    } else if (!regulationViolation && totalDisbursedKsh > budgetStats.remainingDailyBudgetKsh) {
      regulationViolation = `Total payout (KSh ${totalDisbursedKsh.toLocaleString()}) exceeds remaining regulated 24h budget cap of KSh ${budgetStats.remainingDailyBudgetKsh.toLocaleString()}.`;
    }

    if (action === 'preview') {
      return jsonSuccess({
        preview: {
          eligibleCount: eligibleUsers.length,
          matchedBeforeCooldown,
          cooldownSkippedCount,
          amountPerUserKsh,
          totalDisbursedKsh,
          balanceType,
          remainingDailyBudgetKsh: budgetStats.remainingDailyBudgetKsh,
          regulationViolation
        }
      });
    }

    // ------------------------------------------------------------------
    // 3. DISTRIBUTE REGULATED BONUS REWARDS TO ELIGIBLE ACTIVE USERS
    // ------------------------------------------------------------------
    if (action !== 'distribute') {
      return jsonError(`Unsupported bonus action "${action}"`, 400);
    }

    const campaignTitle = (body.campaignTitle || body.reason || 'Active Partner Appreciation Bonus').trim().slice(0, 120);
    if (!campaignTitle) {
      return jsonError('Please provide a bonus campaign title or reason', 400);
    }

    if (regulationViolation) {
      return jsonError(regulationViolation, 400);
    }

    if (eligibleUsers.length === 0) {
      const cooldownHint = cooldownSkippedCount > 0
        ? ` (${cooldownSkippedCount} active user(s) were skipped because they already received a bonus within the ${regulations.cooldown_hours}h cooldown regulation.)`
        : '';
      return jsonError(`No eligible active users matched the selected criteria.${cooldownHint}`, 400);
    }

    const distributionId = generateId('bon');
    await env.DB.prepare(`
      INSERT INTO bonus_distributions (
        id, campaign_title, amount_per_user_ksh, recipient_count, total_disbursed_ksh,
        balance_type, eligibility_scope, package_filter_id, min_approved_views, admin_id, created_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      distributionId,
      campaignTitle,
      amountPerUserKsh,
      eligibleUsers.length,
      totalDisbursedKsh,
      balanceType,
      scope,
      (body.packageId && body.packageId !== 'all') ? String(body.packageId) : null,
      Math.max(0, parseInt(body.minApprovedViews, 10) || 0),
      admin.id,
      now
    ).run();

    for (const u of eligibleUsers) {
      let wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(u.id).first();
      if (!wallet) {
        const walletId = generateId('wal');
        await env.DB.prepare(`
          INSERT INTO wallets (
            id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh,
            surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at
          ) VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
        `).bind(walletId, u.id, now).run().catch(() => {});
        wallet = await env.DB.prepare('SELECT * FROM wallets WHERE user_id = ?').bind(u.id).first();
      }

      const curAvail = wallet?.available_balance_ksh || 0;
      const curRef = wallet?.referrals_balance_ksh || 0;
      const curSurveys = wallet?.surveys_balance_ksh || 0;
      const curViews = ((wallet?.views_balance_ksh || 0) === 0 && curAvail > (curRef + curSurveys))
        ? (curAvail - curRef - curSurveys)
        : (wallet?.views_balance_ksh || 0);

      const nextViews = balanceType === 'views' ? curViews + amountPerUserKsh : curViews;
      const nextRef = balanceType === 'referrals' ? curRef + amountPerUserKsh : curRef;
      const nextSurveys = balanceType === 'surveys' ? curSurveys + amountPerUserKsh : curSurveys;
      const nextAvail = nextViews + nextRef + nextSurveys;
      const nextLifetime = (wallet?.lifetime_earnings_ksh || 0) + amountPerUserKsh;

      await env.DB.prepare(`
        UPDATE wallets
        SET views_balance_ksh = ?,
            referrals_balance_ksh = ?,
            surveys_balance_ksh = ?,
            available_balance_ksh = ?,
            lifetime_earnings_ksh = ?,
            updated_at = ?
        WHERE user_id = ?
      `).bind(nextViews, nextRef, nextSurveys, nextAvail, nextLifetime, now, u.id).run();

      const txId = generateId('tx_bon');
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        u.id,
        amountPerUserKsh,
        nextAvail,
        distributionId,
        `Active User Bonus (${campaignTitle}): +KSh ${amountPerUserKsh.toLocaleString()} to ${balanceType}`,
        now
      ).run();

      const logId = generateId('brl');
      await env.DB.prepare(`
        INSERT INTO bonus_recipient_logs (id, distribution_id, user_id, amount_ksh, balance_type, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(logId, distributionId, u.id, amountPerUserKsh, balanceType, now).run();
    }

    await createAuditLog(env, {
      adminId: admin.id,
      action: 'DISTRIBUTE_ACTIVE_BONUS',
      targetType: 'bonus_distribution',
      targetId: distributionId,
      details: {
        campaignTitle,
        amountPerUserKsh,
        recipientCount: eligibleUsers.length,
        cooldownSkippedCount,
        totalDisbursedKsh,
        balanceType,
        scope
      },
      ip
    });

    const refreshed = await getRegulationsAndBudget(env.DB);
    return jsonSuccess({
      message: `Awarded KSh ${amountPerUserKsh.toLocaleString()} bonus (${campaignTitle}) to ${eligibleUsers.length} active partner(s) — total KSh ${totalDisbursedKsh.toLocaleString()}!`,
      distribution: {
        id: distributionId,
        campaignTitle,
        amountPerUserKsh,
        recipientCount: eligibleUsers.length,
        cooldownSkippedCount,
        totalDisbursedKsh,
        balanceType
      },
      ...refreshed
    });
  } catch (err) {
    console.error('Admin bonuses POST error:', err);
    return jsonError('Failed to process regulated active user bonus', 500);
  }
}

