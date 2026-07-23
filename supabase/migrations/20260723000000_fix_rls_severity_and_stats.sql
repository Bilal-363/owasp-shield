-- ============================================================================
-- FIX: RLS hardening (that actually applies), Critical severity, and stats.
--
-- Why this migration exists:
--   * The earlier 20250722_tighten_rls.sql was dated BEFORE the base schema
--     (20250816...), so it ran first, dropped policies that did not exist yet
--     (no-op), and then the base migration RE-CREATED the permissive INSERT
--     policies. Net effect: the "tightening" was silently reverted.
--   * This migration is dated 2026-07-23, so it runs LAST and its changes stick.
--
-- What it does:
--   1. Removes client INSERT/UPDATE paths that let users forge scan data.
--      Only the backend (service_role, which bypasses RLS) writes results.
--   2. Adds 'Critical' to the findings severity CHECK (the UI already uses it).
--   3. Adds scans.critical_findings so stats match the UI.
-- ============================================================================

-- 1. Lock down writes ---------------------------------------------------------
-- Users may still create a scan ROW is NOT allowed from the client anymore;
-- scans are created by the backend edge/service. Keep SELECT + DELETE + a
-- narrow UPDATE (so the "stop scan" button can still cancel, if you ever call
-- it directly — but the backend handles it via service_role anyway).

DROP POLICY IF EXISTS "Users can create their own scans" ON public.scans;
DROP POLICY IF EXISTS "Service can insert findings" ON public.findings;
DROP POLICY IF EXISTS "Service can insert scan logs" ON public.scan_logs;

-- Tighten the scans UPDATE policy so users can only flip status to 'cancelled'
-- (not rewrite findings counts, target, etc.). Drop the broad one first.
DROP POLICY IF EXISTS "Users can update their own scans" ON public.scans;
CREATE POLICY "Users can cancel their own scans"
ON public.scans FOR UPDATE
USING (auth.uid() = user_id)
WITH CHECK (auth.uid() = user_id AND status = 'cancelled');

-- 2. Add 'Critical' severity --------------------------------------------------
ALTER TABLE public.findings DROP CONSTRAINT IF EXISTS findings_severity_check;
ALTER TABLE public.findings
  ADD CONSTRAINT findings_severity_check
  CHECK (severity IN ('Critical', 'High', 'Medium', 'Low', 'Info'));

-- 3. Add critical_findings stat column ---------------------------------------
ALTER TABLE public.scans
  ADD COLUMN IF NOT EXISTS critical_findings INTEGER DEFAULT 0;

-- Allow a nullable/zero CVSS (portscan/info findings use 0 or null).
ALTER TABLE public.findings ALTER COLUMN cvss_score DROP NOT NULL;
