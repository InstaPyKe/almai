-- ====================================================================
-- ALMAI ADS PRODUCTS — Migration 0007
-- Add submission_tickets column to users table
-- Enables admin to grant submission tickets waiving the 18-hour cooldown rule
-- ====================================================================

ALTER TABLE users ADD COLUMN submission_tickets INTEGER NOT NULL DEFAULT 0;

