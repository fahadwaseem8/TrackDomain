-- Migration: create the tracked_domains table
-- Run this in your Supabase project: SQL Editor → New query → paste and run.

CREATE TABLE IF NOT EXISTS public.tracked_domains (
    id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID        NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    domain      TEXT        NOT NULL CHECK (char_length(trim(domain)) >= 3),
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Prevent the same user from adding the same domain twice
    CONSTRAINT tracked_domains_user_domain_unique UNIQUE (user_id, domain)
);

-- Index so per-user queries stay fast as the table grows
CREATE INDEX IF NOT EXISTS tracked_domains_user_id_idx
    ON public.tracked_domains (user_id);

-- ────────────────────────────────────────────────
-- Row-Level Security
-- Each user can only see and modify their own rows.
-- ────────────────────────────────────────────────
ALTER TABLE public.tracked_domains ENABLE ROW LEVEL SECURITY;

CREATE POLICY "users_select_own_domains"
    ON public.tracked_domains FOR SELECT
    USING (auth.uid() = user_id);

CREATE POLICY "users_insert_own_domains"
    ON public.tracked_domains FOR INSERT
    WITH CHECK (auth.uid() = user_id);

CREATE POLICY "users_delete_own_domains"
    ON public.tracked_domains FOR DELETE
    USING (auth.uid() = user_id);
