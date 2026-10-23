# ALMAI ADS PRODUCTS — Cloudflare Pages & D1 Production Application

A real, production-ready WhatsApp advertising and monetization platform built specifically for Cloudflare Pages with native Cloudflare D1 database and Cloudflare Pages Functions.

---

## 🌟 Tech Stack & Architecture

- **Frontend:** HTML5, CSS3 (Modern Vanilla CSS conforming to custom brand design palette), Vanilla JavaScript (No React, No Vue, No Tailwind).
- **Hosting:** Cloudflare Pages connected to GitHub.
- **Database:** Cloudflare D1 (Serverless distributed SQL SQLite database).
- **Backend / API:** Cloudflare Pages Functions (`functions/api/`).
- **Security:**
  - Web Crypto API (`crypto.subtle` PBKDF2-SHA256 password hashing with unique 16-byte random salts).
  - Secure unpredictable session tokens with `HttpOnly`, `Secure`, `SameSite=Lax` cookies.
  - Server-side 24-hour task submission cooldown enforcement using unix timestamps.
  - Double-entry auditable ledger for wallets, earnings, reserved funds, and withdrawals.
  - Role-based Access Control (RBAC) protecting administrative actions and audit logs.
  - 100% Parameterized SQL statements with `.bind()`.

---

## 🎨 Design System Palette

The application strictly implements the required color tokens:
- **Background Cream:** `#F8F0E2`
- **Primary Purple Buttons:** `#6D28D9`
- **Deep Purple Headings:** `#54218F`
- **Light Purple Accents:** `#8B5CF6`
- **Charcoal Text:** `#242124`
- **Warning Red:** `#B91C1C`
- **White Cards:** `#FFFFFF`
- **Beige Borders:** `#E8DFD2`

---

## 📁 Project Structure

```
almai/
├── index.html                           # Single-page UI with 4 views & interactive modals
├── wrangler.toml                        # Cloudflare Pages & D1 database binding config
├── package.json                         # Scripts for dev and D1 migrations
├── README.md                            # Comprehensive setup and deployment manual
├── migrations/
│   └── 0001_initial_schema.sql          # 13 D1 database tables, indexes, constraints, seeds
└── functions/
    ├── _middleware.js                   # Optional global middleware
    └── api/
        ├── _utils.js                    # Web Crypto, session auth, DB helpers, audit logs
        ├── packages.js                  # GET tiers & POST activate/upgrade
        ├── tasks.js                     # GET user submissions & POST new proof (24h cooldown)
        ├── withdrawals.js               # GET withdrawals & POST reserve funds
        ├── inquiries.js                 # POST business advertiser inquiry
        ├── setup-admin.js               # Secure admin provisioning endpoint
        ├── auth/
        │   ├── register.js              # User registration with PBKDF2 & wallet creation
        │   ├── login.js                 # Authentication & HttpOnly cookie issuance
        │   ├── logout.js                # Invalidate D1 session & clear cookie
        │   └── me.js                    # Session check & live financial stats
        ├── evidence/
        │   └── [id].js                  # Protected screenshot proof image streamer
        └── admin/
            ├── tasks.js                 # Review queue (Approve & credit wallet / Reject)
            ├── withdrawals.js           # Payout queue (Mark paid with M-Pesa ref / Refund)
            ├── packages.js              # Configure pricing & reward rates
            ├── stats.js                 # Real-time platform financials & views metrics
            └── audit-logs.js            # Admin audit log records
```

---

## 🚀 Local Development Setup

### 1. Prerequisites
Ensure you have Node.js (v18+) and npm installed.

### 2. Run Local Database Migrations
Create and execute the schema against local D1 emulation:
```bash
npx wrangler d1 execute almai-db --local --file=./migrations/0001_initial_schema.sql
```

### 3. Launch the Local Development Server
Start Cloudflare Pages dev server with the D1 database binding:
```bash
npm run dev
# Or directly:
npx wrangler pages dev . --d1 DB=almai-db --compatibility-date=2024-04-01
```

Open your browser at `http://localhost:8788`.

---

## ☁️ Cloudflare Production Deployment

### Step 1: Create the Cloudflare D1 Database
In your terminal, authenticate with Wrangler and create your production database:
```bash
npx wrangler d1 create almai-db
```
Wrangler will output your `database_id` and configuration snippet. Example:
```toml
[[d1_databases]]
binding = "DB"
database_name = "almai-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
```
Update `wrangler.toml` with this `database_id`.

### Step 2: Apply SQL Migrations to Production D1
Run the schema migration against the remote production database:
```bash
npx wrangler d1 execute almai-db --remote --file=./migrations/0001_initial_schema.sql
```

### Step 3: Deploy to Cloudflare Pages
You can deploy either via GitHub integration or directly via Wrangler CLI:

#### Method A: Direct CLI Deployment
```bash
npx wrangler pages deploy . --project-name=almai
```

#### Method B: GitHub Continuous Deployment (Recommended)
1. Push your repository to GitHub.
2. In the [Cloudflare Dashboard](https://dash.cloudflare.com/):
   - Go to **Workers & Pages** > **Create application** > **Pages** > **Connect to Git**.
   - Select your repository.
   - Set **Build command**: *(leave empty)*
   - Set **Build output directory**: `.`
   - Click **Save and Deploy**.

### Step 4: Bind the D1 Database in Cloudflare Pages Dashboard
1. Go to your Pages project in Cloudflare Dashboard: **Settings** > **Functions**.
2. Scroll to **D1 database bindings**.
3. Click **Add binding**:
   - **Variable name:** `DB` (Must be exact)
   - **D1 database:** Select `almai-db`
4. Trigger a new deployment or retry deployment for the binding to activate.

### Step 5: Configure Production Secrets
Under **Settings** > **Environment variables** (Production), configure:
- `ADMIN_SETUP_SECRET`: A strong secret key used for administrative promotion.
- `MPESA_PAYBILL_NUMBER`: e.g. `Paybill 522533 (Account: 8106675)` or your Till Number.
- *(Optional for automated STK Push)*:
  - `MPESA_CONSUMER_KEY`
  - `MPESA_CONSUMER_SECRET`
  - `MPESA_PASSKEY`
  - `MPESA_SHORTCODE`

---

## 🛡️ Administrative Account Setup

The very first user who registers on a fresh database is automatically assigned the `admin` role.

To promote any existing or specific user to Administrator in production securely:
```bash
curl -X POST https://your-project.pages.dev/api/setup-admin \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@almai.com",
    "setupSecret": "<YOUR_ADMIN_SETUP_SECRET>"
  }'
```

Once logged in as an administrator:
1. An **"🛡️ Admin"** button will appear in the top navigation bar.
2. The Admin Center enables:
   - **Task Review Queue:** View full screenshots uploaded by partners, enter verified views, and approve (which atomically calculates rewards and credits partner wallets) or reject with feedback.
   - **Withdrawals Queue:** View requested M-Pesa payouts, disburse funds, enter the official Safaricom M-Pesa receipt code, and mark complete. Alternatively, reject to automatically refund reserved funds back into the partner's available balance.
   - **Audit Logs:** View all administrative actions with IP addresses and timestamps.
   - **Platform Stats:** Monitor total registered partners, view liabilities, and disbursed payouts.

---

## 🧪 Testing Checklist

1. **Registration & Login:**
   - Register a user at `/` by clicking "Get Started".
   - Confirm session cookie `almai_session` is set with `HttpOnly` and `SameSite=Lax`.
   - Verify `/api/auth/me` returns the authenticated profile.
2. **Package Activation:**
   - Go to "Products & Services", select Starter (KSh 200) or Growth (KSh 500).
   - Enter payment phone and M-Pesa confirmation code.
   - Verify package becomes active in dashboard.
3. **Task Cooldown & Submission:**
   - Click "Submit 24h WhatsApp Proof".
   - Upload screenshot proof and enter views.
   - Confirm submission appears in "Task Submissions" table as `pending`.
   - Verify that trying to submit again immediately triggers the 24-hour cooldown lock on both frontend and server.
4. **Administrative Review:**
   - Open Admin Panel -> "Task Submissions Queue".
   - Inspect evidence image proof.
   - Click "Approve", enter verified views (e.g. 50 views @ KSh 50/view = KSh 2,500).
   - Verify partner's wallet immediately reflects the new Available Balance.
5. **Withdrawals & Funds Reservation:**
   - Request withdrawal of KSh 500.
   - Verify KSh 500 moves from "Available Balance" to "Reserved Balance".
   - In Admin Panel -> "Withdrawals Queue", enter Safaricom M-Pesa receipt code (e.g. `QWE78TY90K`) and mark completed.
   - Verify Reserved Balance clears and Lifetime Withdrawn increments.
