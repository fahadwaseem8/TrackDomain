-- Migration: shared WHOIS data table
-- Run in Supabase SQL Editor: paste and run.
--
-- Design: one row per domain name, shared across all users who track it.
-- Any authenticated user can read or update it; the API layer enforces
-- that a user must track the domain before they can trigger a fetch.

CREATE TABLE IF NOT EXISTS public.domain_whois (
    domain      TEXT        PRIMARY KEY,
    raw         TEXT,
    parsed      JSONB,
    fetched_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ──────────────────────────────────────────────────────────────────
-- Row-Level Security
-- Any confirmed (authenticated) user can read and upsert WHOIS data.
-- There is no per-user ownership — WHOIS data is inherently public.
-- ──────────────────────────────────────────────────────────────────
ALTER TABLE public.domain_whois ENABLE ROW LEVEL SECURITY;

CREATE POLICY "authenticated_read_whois"
    ON public.domain_whois FOR SELECT
    TO authenticated
    USING (true);

CREATE POLICY "authenticated_insert_whois"
    ON public.domain_whois FOR INSERT
    TO authenticated
    WITH CHECK (true);

CREATE POLICY "authenticated_update_whois"
    ON public.domain_whois FOR UPDATE
    TO authenticated
    USING (true)
    WITH CHECK (true);
