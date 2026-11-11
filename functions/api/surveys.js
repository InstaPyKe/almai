// ====================================================================
// ALMAI ADS PRODUCTS — Cloudflare Pages Functions
// Route: GET, POST /api/surveys
// Paid Consumer Surveys & Instant M-Pesa Rewards System
// ====================================================================

import { jsonError, jsonSuccess, requireAuth, generateId, syncAndGetUserPackageState, TRIAL_EXPIRED_LOCKOUT_MESSAGE } from './_utils.js';

// Default initial corporate surveys seeded into the database
const SEED_SURVEYS = [
  {
    id: 'srv_saf_mpesa_2026',
    title: 'Safaricom M-Pesa & Mobile Banking Consumer Pulse',
    category: 'Telecom & Fintech',
    description: 'Share your daily mobile money habits, Fuliza usage, and merchant Till preferences to help Kenyan fintechs improve zero-fee transfers.',
    reward_ksh: 80,
    estimated_minutes: 3,
    questions: JSON.stringify([
      {
        id: 'q1',
        text: 'How frequently do you use Safaricom M-Pesa to pay for daily items (Till / Paybill)?',
        options: ['Multiple times daily', 'Once daily', '2-4 times a week', 'Rarely / Cash preferred']
      },
      {
        id: 'q2',
        text: 'Have you used M-Pesa Fuliza or overdraft services in the past 30 days?',
        options: ['Yes, regularly for emergencies', 'Yes, once or twice', 'No, never used Fuliza', 'Prefer mobile loans (Tala / Branch)']
      },
      {
        id: 'q3',
        text: 'What feature would you like to see improved most on the M-Pesa Super App?',
        options: ['Lower transaction fees', 'Zero data charges without bundles', 'Better expense tracking & budgeting', 'Faster customer care resolution']
      },
      {
        id: 'q4',
        text: 'Would you consider using Airtel Money if transaction fees were 50% lower than M-Pesa?',
        options: ['Definitely yes, already using both', 'Probably yes if merchants accept it', 'Unlikely, M-Pesa is universally accepted', 'Not interested']
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5000
  },
  {
    id: 'srv_ecommerce_delivery',
    title: 'Kenya E-Commerce & Rapid Delivery (Jumia, Glovo & Kilimall)',
    category: 'E-Commerce & Logistics',
    description: 'Voice your experience regarding doorstep delivery times, package safety, and cash on delivery vs M-Pesa online prepayments.',
    reward_ksh: 70,
    estimated_minutes: 3,
    questions: JSON.stringify([
      {
        id: 'q1',
        text: 'Which online shopping platform do you shop with most often in Kenya?',
        options: ['Jumia Kenya', 'Kilimall', 'Glovo / Uber Eats for quick essentials', 'Social media (Instagram / WhatsApp / TikTok sellers)', 'None']
      },
      {
        id: 'q2',
        text: 'What is your preferred payment method when ordering items online?',
        options: ['M-Pesa payment upon physical delivery', 'Instant M-Pesa STK Push during checkout', 'Credit / Debit Card', 'Cash on Delivery']
      },
      {
        id: 'q3',
        text: 'What is the most frustrating issue you experience with Kenyan online shopping?',
        options: ['Delivery takes too long / missed timelines', 'Item received looks different from website photos', 'High delivery shipping fees outside Nairobi', 'Complicated return and refund processes']
      },
      {
        id: 'q4',
        text: 'What is the maximum you are willing to pay for same-day delivery within your county?',
        options: ['Free delivery only', 'KSh 100 - KSh 150', 'KSh 200 - KSh 350', 'KSh 400+ for guaranteed within 2 hours']
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5000
  },
  {
    id: 'srv_home_internet_5g',
    title: 'Smartphone & 4G/5G Home Internet Usage Trends',
    category: 'Tech & Connectivity',
    description: 'Help Kenyan internet service providers design affordable Wi-Fi and 5G wireless router packages for residential homes.',
    reward_ksh: 60,
    estimated_minutes: 2,
    questions: JSON.stringify([
      {
        id: 'q1',
        text: 'What is your primary internet connection at home?',
        options: ['Home Fiber (Safaricom, Zuku, Faiba)', '5G / 4G Wi-Fi Wireless Router', 'Daily / Weekly mobile phone data bundles', 'Office / Public Wi-Fi']
      },
      {
        id: 'q2',
        text: 'Approximately how much do you spend monthly on all internet services combined?',
        options: ['Under KSh 1,000', 'KSh 1,000 - KSh 2,500', 'KSh 2,500 - KSh 4,500', 'Over KSh 5,000']
      },
      {
        id: 'q3',
        text: 'What do you use the highest percentage of your internet bandwidth for?',
        options: ['WhatsApp & Social media videos (TikTok / Instagram / YouTube)', 'Remote work, video meetings & freelancing', 'Online TV streaming (Netflix / Showmax / DSTV)', 'Online studies & research']
      },
      {
        id: 'q4',
        text: 'Which smartphone brand are you currently using as your primary device?',
        options: ['Samsung', 'Transsion (Tecno / Infinix / Itel)', 'Xiaomi / Redmi', 'Apple iPhone', 'Oppo / Vivo / Realme']
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5000
  },
  {
    id: 'srv_digital_loans_hustler',
    title: 'Digital Micro-Loans & Mobile Credit Preferences',
    category: 'Financial Services',
    description: 'Evaluate loan access, interest rates, repayment periods, and borrowing behavior among Kenyan creators and digital entrepreneurs.',
    reward_ksh: 90,
    estimated_minutes: 4,
    questions: JSON.stringify([
      {
        id: 'q1',
        text: 'Which mobile lending service have you used in the last 6 months?',
        options: ['Hustler Fund', 'M-Shwari / KCB M-Pesa', 'Digital apps (Tala, Branch, Zenka)', 'Bank mobile apps (Equity, Co-op)', 'Have not borrowed from mobile lenders']
      },
      {
        id: 'q2',
        text: 'What is your primary reason for taking a mobile digital loan?',
        options: ['Business inventory / working capital', 'Household emergencies / medical', 'School fees or rent assistance', 'Airtime / personal utilities', 'Never borrow']
      },
      {
        id: 'q3',
        text: 'What loan repayment duration works best for your cash flow?',
        options: ['Daily or 14-day cycle', '30-day single installment', '3 to 6 months flexible monthly installments', '12+ months long-term']
      },
      {
        id: 'q4',
        text: 'How satisfied are you with interest rates and processing fees on Kenyan digital loans?',
        options: ['Fair & affordable (e.g. Hustler Fund)', 'Acceptable for quick emergencies', 'Too high / predatory interest rates', 'Prefer saving in SACCO / Chamas instead']
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5000
  },
  {
    id: 'srv_fmcg_supermarkets',
    title: 'Daily FMCG & Packaged Foods Brand Loyalty',
    category: 'Retail & Household',
    description: 'Tell top manufacturers your choices on household maize flour, milk, cooking oil, and soap to guide supermarket pricing.',
    reward_ksh: 50,
    estimated_minutes: 2,
    questions: JSON.stringify([
      {
        id: 'q1',
        text: 'Where do you purchase the majority of your household groceries?',
        options: ['Local neighborhood kiosk / Duka', 'Large Supermarkets (Naivas, Quickmart, Carrefour)', 'Open-air county food market (Marikiti)', 'Online grocery delivery apps']
      },
      {
        id: 'q2',
        text: 'When buying maize flour (Unga wa Sembe), which brand do you trust most?',
        options: ['Jogoo', 'Raha / Pembe', 'Hostess / Soko', 'Taifa / Ndovu', 'Local Posho Mill flour']
      },
      {
        id: 'q3',
        text: 'What factor most strongly influences your choice when buying cooking oil?',
        options: ['Price & volume offers / discounts', 'Health benefits (Cholesterol free / Fortified with vitamins)', 'Familiar brand reputation (Elianto, Rina, Fresh Fri)', 'Packaging convenience']
      },
      {
        id: 'q4',
        text: 'How has inflation impacted your monthly household shopping basket this year?',
        options: ['Switched to more affordable alternative brands', 'Reduced quantities purchased per trip', 'Shopping habits remained the same', 'Started buying in bulk wholesale to save']
      }
    ]),
    target_package_id: null,
    is_active: 1,
    completions_count: 0,
    max_completions: 5000
  }
];

/**
 * Defensive schema migration for Surveys & Wallet balances
 */
async function ensureSurveysSchema(env) {
  try {
    await env.DB.prepare("ALTER TABLE wallets ADD COLUMN surveys_balance_ksh INTEGER NOT NULL DEFAULT 0").run().catch(() => { });
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS surveys (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        category TEXT NOT NULL DEFAULT 'Consumer Habits',
        description TEXT NOT NULL,
        reward_ksh INTEGER NOT NULL DEFAULT 60,
        estimated_minutes INTEGER NOT NULL DEFAULT 3,
        questions TEXT NOT NULL,
        target_package_id TEXT,
        is_active INTEGER NOT NULL DEFAULT 1,
        completions_count INTEGER NOT NULL DEFAULT 0,
        max_completions INTEGER DEFAULT 5000,
        created_at INTEGER NOT NULL
      )
    `).run().catch(() => { });

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS survey_responses (
        id TEXT PRIMARY KEY,
        survey_id TEXT NOT NULL REFERENCES surveys(id),
        user_id TEXT NOT NULL REFERENCES users(id),
        answers TEXT NOT NULL,
        reward_amount_ksh INTEGER NOT NULL,
        completed_at INTEGER NOT NULL,
        UNIQUE(survey_id, user_id)
      )
    `).run().catch(() => { });

    // Check if initial surveys exist, seed if empty
    const countRow = await env.DB.prepare("SELECT COUNT(*) as cnt FROM surveys").first().catch(() => null);
    if (!countRow || countRow.cnt === 0) {
      const now = Math.floor(Date.now() / 1000);
      for (const s of SEED_SURVEYS) {
        await env.DB.prepare(`
          INSERT INTO surveys (id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          s.id, s.title, s.category, s.description, s.reward_ksh, s.estimated_minutes, s.questions, s.target_package_id, s.is_active, s.completions_count, s.max_completions, now
        ).run().catch(() => { });
      }
    }
  } catch (e) {
    console.error('ensureSurveysSchema error:', e);
  }
}

/**
 * GET /api/surveys
 * List active surveys, user's completion status, and survey earnings
 */
export async function onRequestGet(context) {
  const { request, env } = context;

  const auth = await requireAuth(request, env);
  if (auth.errorResponse) return auth.errorResponse;

  const user = auth.user;

  try {
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);

    await ensureSurveysSchema(env);

    // 1. Fetch user's responses
    const { results: userResponses } = await env.DB.prepare(`
      SELECT survey_id, reward_amount_ksh, completed_at
      FROM survey_responses
      WHERE user_id = ?
    `).bind(user.id).all();

    const completedMap = new Map();
    let totalSurveyEarningsKsh = 0;
    if (userResponses && userResponses.length > 0) {
      for (const r of userResponses) {
        completedMap.set(r.survey_id, {
          completedAt: r.completed_at,
          rewardAmountKsh: r.reward_amount_ksh
        });
        totalSurveyEarningsKsh += Number(r.reward_amount_ksh || 0);
      }
    }

    // 2. Fetch all active surveys
    const { results: surveyRows } = await env.DB.prepare(`
      SELECT id, title, category, description, reward_ksh, estimated_minutes, questions, target_package_id, is_active, completions_count, max_completions, created_at
      FROM surveys
      WHERE is_active = 1
      ORDER BY created_at DESC
    `).all();

    // 3. User wallet sub-balance
    const wallet = await env.DB.prepare(`
      SELECT surveys_balance_ksh, available_balance_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first().catch(() => null);

    const surveysBalanceKsh = wallet ? Number(wallet.surveys_balance_ksh || 0) : 0;

    // 4. Transform survey rows
    let availableCount = 0;
    const formattedSurveys = (surveyRows || []).map(row => {
      let parsedQuestions = [];
      try {
        parsedQuestions = JSON.parse(row.questions);
      } catch (e) {
        parsedQuestions = [];
      }

      const userCompletion = completedMap.get(row.id);
      const isCompleted = Boolean(userCompletion);

      if (!isCompleted) {
        availableCount++;
      }

      return {
        id: row.id,
        title: row.title,
        category: row.category,
        description: row.description,
        rewardKsh: row.reward_ksh,
        estimatedMinutes: row.estimated_minutes,
        questionsCount: parsedQuestions.length,
        questions: parsedQuestions, // Frontend will render these when user opens survey
        completionsCount: row.completions_count,
        maxCompletions: row.max_completions,
        isCompleted,
        completedAt: userCompletion ? userCompletion.completedAt : null,
        userEarnedRewardKsh: userCompletion ? userCompletion.rewardAmountKsh : null
      };
    });

    return jsonSuccess({
      surveys: formattedSurveys,
      isTrialExpiredLockout: pkgState.isTrialExpiredLockout,
      stats: {
        surveysBalanceKsh,
        availableSurveysCount: availableCount,
        completedSurveysCount: completedMap.size,
        totalSurveyEarningsKsh
      }
    });

  } catch (err) {
    console.error('Fetch surveys error:', err);
    return jsonError('Failed to load surveys', 500);
  }
}

/**
 * POST /api/surveys
 * Submit responses for a paid survey and receive instant wallet credit
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

  const { surveyId, answers } = body;

  if (!surveyId) {
    return jsonError('surveyId is required', 400);
  }

  if (!answers || typeof answers !== 'object' || Array.isArray(answers) || Object.keys(answers).length === 0) {
    return jsonError('Please provide your answers for all survey questions', 400);
  }

  try {
    const pkgState = await syncAndGetUserPackageState(env.DB, user.id);
    if (pkgState.isTrialExpiredLockout) {
      return jsonError(TRIAL_EXPIRED_LOCKOUT_MESSAGE, 403, { trialExpired: true, code: 'TRIAL_EXPIRED' });
    }

    await ensureSurveysSchema(env);

    // 1. Fetch survey
    const survey = await env.DB.prepare(`
      SELECT id, title, reward_ksh, questions, is_active, completions_count, max_completions
      FROM surveys
      WHERE id = ?
      LIMIT 1
    `).bind(surveyId).first();

    if (!survey) {
      return jsonError('Survey campaign not found', 404);
    }

    if (survey.is_active !== 1) {
      return jsonError('This survey campaign has expired or been paused by the sponsor.', 400);
    }

    if (survey.max_completions && survey.completions_count >= survey.max_completions) {
      return jsonError('This survey campaign has reached its maximum respondent capacity.', 400);
    }

    // 2. Prevent duplicate completion by same user
    const existing = await env.DB.prepare(`
      SELECT id, completed_at, reward_amount_ksh
      FROM survey_responses
      WHERE survey_id = ? AND user_id = ?
      LIMIT 1
    `).bind(surveyId, user.id).first();

    if (existing) {
      return jsonError('You have already completed this survey and received your payout reward.', 409);
    }

    // 3. Validate answers against survey questions
    let parsedQuestions = [];
    try {
      parsedQuestions = JSON.parse(survey.questions);
    } catch (e) {
      parsedQuestions = [];
    }

    for (const q of parsedQuestions) {
      const ans = answers[q.id];
      if (!ans || typeof ans !== 'string' || !ans.trim()) {
        return jsonError(`Please answer question: "${q.text}"`, 400);
      }
    }

    const rewardKsh = Math.max(1, parseInt(survey.reward_ksh, 10) || 50);
    const now = Math.floor(Date.now() / 1000);
    const responseId = generateId('sr');
    const txId = generateId('wtx');

    // 4. Ensure user wallet exists
    let wallet = await env.DB.prepare(`
      SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, lifetime_earnings_ksh
      FROM wallets
      WHERE user_id = ?
      LIMIT 1
    `).bind(user.id).first();

    if (!wallet) {
      const walId = generateId('wal');
      await env.DB.prepare(`
        INSERT INTO wallets (id, user_id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at)
        VALUES (?, ?, 0, 0, 0, 0, 0, 0, 0, ?)
      `).bind(walId, user.id, now).run().catch(() => { });
      wallet = await env.DB.prepare(`
        SELECT id, available_balance_ksh, views_balance_ksh, referrals_balance_ksh, surveys_balance_ksh, lifetime_earnings_ksh
        FROM wallets
        WHERE user_id = ?
        LIMIT 1
      `).bind(user.id).first();
    }

    // 5. Insert survey response record
    const insertRes = await env.DB.prepare(`
      INSERT INTO survey_responses (id, survey_id, user_id, answers, reward_amount_ksh, completed_at)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(
      responseId,
      surveyId,
      user.id,
      JSON.stringify(answers),
      rewardKsh,
      now
    ).run();

    if (!insertRes.success) {
      return jsonError('Failed to record survey response. Please try again.', 500);
    }

    // 6. Increment completions count on survey
    await env.DB.prepare(`
      UPDATE surveys
      SET completions_count = completions_count + 1
      WHERE id = ?
    `).bind(surveyId).run().catch(() => { });

    // 7. Atomically credit wallet surveys balance, available balance & lifetime earnings
    const currentSurveysBal = Number(wallet?.surveys_balance_ksh || 0);
    const currentAvailBal = Number(wallet?.available_balance_ksh || 0);
    const currentViewsBal = Number(wallet?.views_balance_ksh || 0);
    const currentRefBal = Number(wallet?.referrals_balance_ksh || 0);
    const currentLifetime = Number(wallet?.lifetime_earnings_ksh || 0);

    const nextSurveysBal = currentSurveysBal + rewardKsh;
    const nextAvailBal = currentAvailBal + rewardKsh;
    const nextLifetime = currentLifetime + rewardKsh;

    await env.DB.prepare(`
      UPDATE wallets
      SET surveys_balance_ksh = surveys_balance_ksh + ?,
          available_balance_ksh = available_balance_ksh + ?,
          lifetime_earnings_ksh = lifetime_earnings_ksh + ?,
          updated_at = ?
      WHERE user_id = ?
    `).bind(rewardKsh, rewardKsh, rewardKsh, now, user.id).run();

    // 8. Record wallet transaction
    await env.DB.prepare(`
      INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
      VALUES (?, ?, ?, 'survey_reward', ?, ?, ?, ?, ?)
    `).bind(
      txId,
      wallet.id,
      user.id,
      rewardKsh,
      nextAvailBal,
      responseId,
      `Paid Survey Reward: ${survey.title} (+KSh ${rewardKsh})`,
      now
    ).run().catch(async (e) => {
      // Fallback if 'survey_reward' type constraint fails: use 'adjustment'
      await env.DB.prepare(`
        INSERT INTO wallet_transactions (id, wallet_id, user_id, type, amount_ksh, balance_after_ksh, reference_id, description, created_at)
        VALUES (?, ?, ?, 'adjustment', ?, ?, ?, ?, ?)
      `).bind(
        txId,
        wallet.id,
        user.id,
        rewardKsh,
        nextAvailBal,
        responseId,
        `Paid Survey Reward: ${survey.title} (+KSh ${rewardKsh})`,
        now
      ).run().catch(() => { });
    });

    return jsonSuccess({
      message: `🎉 Congratulations! You have successfully completed the survey. KSh ${rewardKsh.toLocaleString()} has been credited to your Surveys Balance!`,
      rewardAmountKsh: rewardKsh,
      surveyId,
      surveyTitle: survey.title,
      completedAt: now,
      wallet: {
        surveysBalanceKsh: nextSurveysBal,
        viewsBalanceKsh: currentViewsBal,
        referralsBalanceKsh: currentRefBal,
        availableBalanceKsh: nextAvailBal
      }
    });

  } catch (err) {
    console.error('Submit survey error:', err);
    return jsonError('Failed to submit survey. Please try again.', 500);
  }
}

