-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0002
-- Admin Portal, User Verification, and WhatsApp Product Posts
-- ====================================================================

-- 1. Product Posts Table (Images & Creatives for WhatsApp Status Downloads)
CREATE TABLE IF NOT EXISTS product_posts (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    brand_name TEXT NOT NULL,
    description TEXT,
    caption TEXT NOT NULL,
    image_url TEXT,
    image_base64 TEXT NOT NULL,
    image_name TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'archived')),
    downloads_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_product_posts_status ON product_posts(status);
CREATE INDEX IF NOT EXISTS idx_product_posts_created ON product_posts(created_at);

-- 2. Seed / Ensure Admin Account
-- Email: almai@admin.co.ke
-- Password: almai12345
-- Salt: a1b2c3d4e5f60718293a4b5c6d7e8f90
-- Hash: 34d565655f84920c15ea79180a187359f904bb2bee5e667b78ae3a0258e84ca3
INSERT OR REPLACE INTO users (
    id, name, email, phone, password_hash, salt, role, status, created_at, updated_at
) VALUES (
    'usr_admin_almai',
    'Almai Administrator',
    'almai@admin.co.ke',
    '0700000000',
    '34d565655f84920c15ea79180a187359f904bb2bee5e667b78ae3a0258e84ca3',
    'a1b2c3d4e5f60718293a4b5c6d7e8f90',
    'admin',
    'active',
    1710000000,
    1710000000
);

-- Ensure Admin Wallet
INSERT OR IGNORE INTO wallets (
    id, user_id, available_balance_ksh, reserved_balance_ksh, lifetime_earnings_ksh, lifetime_withdrawn_ksh, updated_at
) VALUES (
    'wal_admin_almai',
    'usr_admin_almai',
    0, 0, 0, 0,
    1710000000
);

-- 3. Seed Default WhatsApp Product Creatives
INSERT OR REPLACE INTO product_posts (
    id, title, brand_name, description, caption, image_base64, image_name, status, downloads_count, created_at
) VALUES 
(
    'prod_almai_growth',
    'Almai Ads Network — Partner Monetization Banner',
    'Almai Ads Network',
    'High-converting official platform banner. Post to WhatsApp Status to earn guaranteed daily payouts on your genuine Kenyan views.',
    'Turn your daily WhatsApp Status views into real cash! 💰 Earn KSh 20 to KSh 100 per verified view paid directly to M-Pesa. Join thousands of Kenyan creators earning every day. Check out: https://almai.pages.dev 🚀',
    'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800" width="800" height="800"><defs><linearGradient id="g1" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%2354218F"/><stop offset="50%" stop-color="%236D28D9"/><stop offset="100%" stop-color="%232E1065"/></linearGradient><linearGradient id="gold" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%23FBBF24"/><stop offset="100%" stop-color="%23D97706"/></linearGradient></defs><rect width="800" height="800" fill="url(%23g1)"/><circle cx="700" cy="100" r="180" fill="%238B5CF6" opacity="0.15"/><circle cx="100" cy="700" r="220" fill="%238B5CF6" opacity="0.12"/><rect x="60" y="60" width="680" height="680" rx="32" fill="none" stroke="%23A78BFA" stroke-width="2" stroke-dasharray="10 6" opacity="0.4"/><rect x="90" y="90" width="220" height="48" rx="24" fill="url(%23gold)"/><text x="200" y="122" font-family="Arial,sans-serif" font-size="18" font-weight="bold" fill="%231E1B4B" text-anchor="middle">OFFICIAL PARTNER</text><text x="400" y="240" font-family="Arial,sans-serif" font-size="46" font-weight="900" fill="%23F8F0E2" text-anchor="middle">MONETIZE YOUR</text><text x="400" y="300" font-family="Arial,sans-serif" font-size="54" font-weight="900" fill="%23FBBF24" text-anchor="middle">WHATSAPP STATUS</text><text x="400" y="360" font-family="Arial,sans-serif" font-size="22" fill="%23EDE9FE" text-anchor="middle">Guaranteed Daily Payouts via M-Pesa</text><rect x="120" y="420" width="560" height="150" rx="20" fill="%23FFFFFF" opacity="0.08"/><text x="400" y="475" font-family="Arial,sans-serif" font-size="34" font-weight="bold" fill="%2334D399" text-anchor="middle">Earn KSh 20 - KSh 100</text><text x="400" y="525" font-family="Arial,sans-serif" font-size="22" fill="%23F8F0E2" text-anchor="middle">Per 24h Verified Status View</text><rect x="200" y="620" width="400" height="60" rx="30" fill="%23047857"/><text x="400" y="658" font-family="Arial,sans-serif" font-size="22" font-weight="bold" fill="%23FFFFFF" text-anchor="middle">almai.pages.dev</text></svg>',
    'almai_partner_promo.svg',
    'active',
    0,
    1710000000
),
(
    'prod_mpesa_merchant',
    'Safaricom M-Pesa Merchant Business Booster',
    'Safaricom Business',
    'Promote Lipa na M-Pesa merchant solutions to business owners and retail operators across Kenya.',
    'Take your retail store, salon, or online business to the next level with Safaricom Lipa Na M-Pesa! 📲✨ Zero transaction delays, instant settlements to your bank, and higher customer trust. Upgrade your till today! 💼',
    'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800" width="800" height="800"><defs><linearGradient id="g2" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%23065F46"/><stop offset="50%" stop-color="%23047857"/><stop offset="100%" stop-color="%23064E3B"/></linearGradient></defs><rect width="800" height="800" fill="url(%23g2)"/><circle cx="680" cy="120" r="160" fill="%2310B981" opacity="0.2"/><rect x="80" y="80" width="640" height="640" rx="28" fill="%23FFFFFF" opacity="0.06"/><rect x="90" y="90" width="180" height="42" rx="21" fill="%23DC2626"/><text x="180" y="117" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="%23FFFFFF" text-anchor="middle">BUSINESS AD</text><text x="400" y="240" font-family="Arial,sans-serif" font-size="44" font-weight="900" fill="%23FFFFFF" text-anchor="middle">ACCEPT PAYMENTS WITH</text><text x="400" y="305" font-family="Arial,sans-serif" font-size="52" font-weight="900" fill="%2334D399" text-anchor="middle">LIPA NA M-PESA</text><text x="400" y="365" font-family="Arial,sans-serif" font-size="24" fill="%23D1FAE5" text-anchor="middle">Till Number & Paybill For Every Business</text><rect x="140" y="420" width="520" height="150" rx="18" fill="%23064E3B"/><text x="400" y="475" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="%23FCD34D" text-anchor="middle">Fast, Secure & Trusted</text><text x="400" y="525" font-family="Arial,sans-serif" font-size="20" fill="%23E6FFFA" text-anchor="middle">Join over 600,000 Kenyan Merchants</text><rect x="220" y="620" width="360" height="56" rx="28" fill="%23FFFFFF"/><text x="400" y="656" font-family="Arial,sans-serif" font-size="20" font-weight="bold" fill="%23047857" text-anchor="middle">Apply Now At Safaricom</text></svg>',
    'mpesa_merchant_ad.svg',
    'active',
    0,
    1710000000
),
(
    'prod_tech_deals',
    'Galaxy Tech Kenya — Flash Gadgets Sale',
    'Galaxy Tech Kenya',
    'Promote genuine smartphone and electronics discounts with countrywide doorstep delivery in Kenya.',
    'Big Gadget Sale in Nairobi! 🔥 Get up to 35% discount on authentic smartphones, powerbanks, wireless earbuds and laptops. Countrywide doorstep delivery & pay on delivery available! 📱💻 Check out the deals today.',
    'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 800 800" width="800" height="800"><defs><linearGradient id="g3" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%231E293B"/><stop offset="50%" stop-color="%230F172A"/><stop offset="100%" stop-color="%23020617"/></linearGradient><linearGradient id="neon" x1="0%" y1="0%" x2="100%" y2="100%"><stop offset="0%" stop-color="%2338BDF8"/><stop offset="100%" stop-color="%236366F1"/></linearGradient></defs><rect width="800" height="800" fill="url(%23g3)"/><circle cx="400" cy="400" r="280" fill="%230284C7" opacity="0.08"/><rect x="90" y="90" width="180" height="42" rx="21" fill="url(%23neon)"/><text x="180" y="117" font-family="Arial,sans-serif" font-size="16" font-weight="bold" fill="%23FFFFFF" text-anchor="middle">FLASH SALE</text><text x="400" y="240" font-family="Arial,sans-serif" font-size="48" font-weight="900" fill="%23FFFFFF" text-anchor="middle">UP TO 35% OFF</text><text x="400" y="305" font-family="Arial,sans-serif" font-size="52" font-weight="900" fill="%2338BDF8" text-anchor="middle">GENUINE GADGETS</text><text x="400" y="365" font-family="Arial,sans-serif" font-size="22" fill="%2394A3B8" text-anchor="middle">Smartphones • Laptops • Accessories</text><rect x="140" y="420" width="520" height="150" rx="18" fill="%231E293B" stroke="%2338BDF8" stroke-width="1.5"/><text x="400" y="475" font-family="Arial,sans-serif" font-size="28" font-weight="bold" fill="%2338BDF8" text-anchor="middle">Nairobi & Countrywide Delivery</text><text x="400" y="525" font-family="Arial,sans-serif" font-size="20" fill="%23F1F5F9" text-anchor="middle">Pay on Delivery • 1 Year Warranty</text><rect x="220" y="620" width="360" height="56" rx="28" fill="url(%23neon)"/><text x="400" y="656" font-family="Arial,sans-serif" font-size="20" font-weight="bold" fill="%23FFFFFF" text-anchor="middle">Order Via WhatsApp Today</text></svg>',
    'galaxy_tech_deals.svg',
    'active',
    0,
    1710000000
);
