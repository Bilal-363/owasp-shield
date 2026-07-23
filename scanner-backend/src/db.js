import { supabase } from './supabase.js';

// All writes use the service-role client (bypasses RLS). The frontend can only
// READ these rows (enforced by RLS), so results cannot be forged by clients.

export async function createScan(userId, targetUrl, tools) {
  // Only insert columns that are guaranteed to exist across schema variants.
  // (scan_type is omitted — some deployments don't have it, and it has a
  // DB-side default when it does.)
  const { data, error } = await supabase
    .from('scans')
    .insert({
      user_id: userId,
      target_url: targetUrl,
      status: 'running',
      tools_used: tools,
      started_at: new Date().toISOString(),
      scan_config: { engine: 'real', current_step: 0, total_steps: 0 },
    })
    .select()
    .single();
  if (error) throw error;
  return data;
}

export async function addLog(scanId, message, level = 'info') {
  try {
    await supabase.from('scan_logs').insert({ scan_id: scanId, message, level });
  } catch (e) {
    console.warn('[db] addLog failed:', e.message);
  }
}

export async function addFinding(scanId, finding) {
  const { error } = await supabase.from('findings').insert({ scan_id: scanId, ...finding });
  if (!error) return;

  // If the DB's severity CHECK doesn't allow 'Critical' yet (migration not
  // applied), downgrade to 'High' so the finding is still recorded.
  if (
    finding.severity === 'Critical' &&
    (error.code === '23514' || /severity/.test(error.message || '') || error.code === 'PGRST204')
  ) {
    const { error: retryErr } = await supabase
      .from('findings')
      .insert({ scan_id: scanId, ...finding, severity: 'High' });
    if (!retryErr) {
      console.warn('[db] severity "Critical" not allowed — recorded as "High". Run the 20260723 migration.');
      return;
    }
    console.warn('[db] addFinding retry failed:', retryErr.message, finding?.title);
    return;
  }
  console.warn('[db] addFinding failed:', error.message, finding?.title);
}

export async function setProgress(scanId, currentStep, totalSteps) {
  const { data } = await supabase.from('scans').select('scan_config').eq('id', scanId).single();
  const cfg = (data?.scan_config && typeof data.scan_config === 'object') ? data.scan_config : {};
  await supabase
    .from('scans')
    .update({ scan_config: { ...cfg, current_step: currentStep, total_steps: totalSteps } })
    .eq('id', scanId);
}

export async function getScan(scanId, userId) {
  const { data, error } = await supabase
    .from('scans')
    .select('*')
    .eq('id', scanId)
    .eq('user_id', userId)
    .single();
  if (error) return null;
  return data;
}

export async function countRecentScans(userId, sinceIso) {
  const { count } = await supabase
    .from('scans')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', userId)
    .gte('created_at', sinceIso);
  return count || 0;
}

export async function finalizeScan(scanId, status, errorMessage = null) {
  // Recompute stats from real findings.
  const { data: findings } = await supabase
    .from('findings')
    .select('severity')
    .eq('scan_id', scanId);

  const stats = (findings || []).reduce(
    (acc, f) => {
      acc.total_findings++;
      if (f.severity === 'Critical') acc.critical_findings++;
      else if (f.severity === 'High') acc.high_risk_findings++;
      else if (f.severity === 'Medium') acc.medium_risk_findings++;
      else if (f.severity === 'Low') acc.low_risk_findings++;
      return acc;
    },
    { total_findings: 0, critical_findings: 0, high_risk_findings: 0, medium_risk_findings: 0, low_risk_findings: 0 }
  );

  const now = new Date().toISOString();

  // Progressive fallback: try the full update, and if a column is missing
  // (PGRST204) keep dropping columns so the scan ALWAYS gets its final status.
  const attempts = [
    {
      status,
      error_message: errorMessage,
      completed_at: now,
      total_findings: stats.total_findings,
      critical_findings: stats.critical_findings,
      high_risk_findings: stats.high_risk_findings,
      medium_risk_findings: stats.medium_risk_findings,
      low_risk_findings: stats.low_risk_findings,
    },
    {
      status,
      error_message: errorMessage,
      completed_at: now,
      total_findings: stats.total_findings,
      high_risk_findings: stats.high_risk_findings,
      medium_risk_findings: stats.medium_risk_findings,
      low_risk_findings: stats.low_risk_findings,
    },
    { status, completed_at: now },
    { status },
  ];

  for (const upd of attempts) {
    const { error } = await supabase.from('scans').update(upd).eq('id', scanId);
    if (!error) return;
    if (error.code !== 'PGRST204' && !/column/.test(error.message || '')) {
      console.warn('[db] finalizeScan failed:', error.message);
      return;
    }
    console.warn('[db] finalizeScan: missing column, retrying with fewer fields. Run the schema SQL to fix properly.');
  }
}

export async function isCancelled(scanId) {
  const { data } = await supabase.from('scans').select('status').eq('id', scanId).single();
  return data?.status === 'cancelled';
}

/**
 * On startup, mark scans left 'running' (from a crash/restart) as failed, so
 * the UI doesn't wait on them forever.
 */
export async function sweepStaleScans(maxAgeMs) {
  const cutoff = new Date(Date.now() - maxAgeMs).toISOString();
  const attempts = [
    { status: 'failed', error_message: 'Scan interrupted (server restarted).', completed_at: new Date().toISOString() },
    { status: 'failed', completed_at: new Date().toISOString() },
    { status: 'failed' },
  ];
  for (const upd of attempts) {
    const { data, error } = await supabase
      .from('scans')
      .update(upd)
      .eq('status', 'running')
      .lt('started_at', cutoff)
      .select('id');
    if (!error) return data?.length || 0;
    if (error.code !== 'PGRST204' && !/column/.test(error.message || '')) {
      console.warn('[db] sweepStaleScans failed:', error.message);
      return 0;
    }
  }
  return 0;
}
