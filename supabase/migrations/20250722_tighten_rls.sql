-- ============================================================================
-- SECURITY FIX #5: Tighten Row Level Security Policies
-- ============================================================================
-- PROBLEM: Authenticated users can INSERT directly into scans, findings,
--          and scan_logs tables via the Supabase client API, bypassing the
--          Edge Function. A malicious user could flood the database with
--          millions of fake records.
--
-- FIX:     Remove INSERT policies for authenticated users on these tables.
--          Only the service_role key (used by Edge Functions) can insert.
--          service_role bypasses RLS entirely, so no new policy is needed.
--
-- TABLES AFFECTED: scans, findings, scan_logs
-- POLICIES KEPT:   SELECT (users see own data), UPDATE on scans (for cancel),
--                  DELETE on scans (user cleanup)
-- ============================================================================

-- Drop the permissive INSERT policy on scans
-- (was: "Users can create their own scans" WITH CHECK auth.uid() = user_id)
DROP POLICY IF EXISTS "Users can create their own scans" ON public.scans;

-- Drop the permissive INSERT policy on findings
-- (was: "Service can insert findings" WITH CHECK scan owned by auth.uid())
DROP POLICY IF EXISTS "Service can insert findings" ON public.findings;

-- Drop the permissive INSERT policy on scan_logs
-- (was: "Service can insert scan logs" WITH CHECK scan owned by auth.uid())
DROP POLICY IF EXISTS "Service can insert scan logs" ON public.scan_logs;

-- ============================================================================
-- NOTE: The Edge Functions use the SUPABASE_SERVICE_ROLE_KEY to create a
-- Supabase client. The service_role key bypasses RLS entirely, so the
-- Edge Functions can still INSERT into these tables without any policy.
--
-- Authenticated users (via the anon key) can still:
--   - SELECT their own scans (policy: "Users can view their own scans")
--   - UPDATE their own scans (policy: "Users can update their own scans")
--   - DELETE their own scans (policy: "Users can delete their own scans")
--   - SELECT findings for their scans (policy: "Users can view findings...")
--   - SELECT logs for their scans (policy: "Users can view logs...")
-- ============================================================================
