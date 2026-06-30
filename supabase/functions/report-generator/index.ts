// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// SECURITY FIX: HTML Escape function
function escapeHtml(text: string): string {
  const map: { [key: string]: string } = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, (m) => map[m]);
}

// SECURITY FIX: Restrict CORS to specific origins
const getCorsHeaders = (origin?: string) => {
  const allowedOrigins = [
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://localhost:3000',
  ];
  
  const isAllowed = origin && allowedOrigins.includes(origin);
  
  return {
    'Access-Control-Allow-Origin': isAllowed ? origin : 'http://localhost:8080',
    'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Max-Age': '3600',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Content-Type': 'application/json',
  };
};

serve(async (req: Request) => {
  const origin = req.headers.get('origin') || undefined;
  const corsHeaders = getCorsHeaders(origin);
  
  // Handle CORS preflight requests
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // SECURITY FIX: Proper auth header validation
    const authHeader = req.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: corsHeaders }
      );
    }

    const token = authHeader.substring(7);
    
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    const { data: { user }, error: authError } = await supabaseClient.auth.getUser(token);

    if (authError || !user) {
      return new Response(
        JSON.stringify({ error: 'Unauthorized' }),
        { status: 401, headers: corsHeaders }
      );
    }

    // SECURITY FIX: Input validation
    let requestBody: any;
    try {
      requestBody = await req.json();
    } catch {
      return new Response(
        JSON.stringify({ error: 'Invalid JSON' }),
        { status: 400, headers: corsHeaders }
      );
    }

    const { scanId, format = 'html' } = requestBody;

    if (!scanId) {
      return new Response(
        JSON.stringify({ error: 'Missing scanId' }),
        { status: 400, headers: corsHeaders }
      );
    }

    // Validate format
    if (!['json', 'csv', 'html'].includes(format)) {
      return new Response(
        JSON.stringify({ error: 'Invalid format' }),
        { status: 400, headers: corsHeaders }
      );
    }

    console.log(`Generating ${format} report`);

    // Get scan data - SECURITY FIX: verify user owns scan
    const { data: scan, error: scanError } = await supabaseClient
      .from('scans')
      .select(`
        *,
        findings (*)
      `)
      .eq('id', scanId)
      .eq('user_id', user.id)
      .single();

    if (scanError || !scan) {
      throw new Error('Scan not found');
    }

    let reportContent: string;
    let fileName: string;
    let contentType: string;

    switch (format) {
      case 'json':
        reportContent = JSON.stringify(scan, null, 2);
        fileName = `scan-report-${scanId}.json`;
        contentType = 'application/json';
        break;
      case 'csv':
        reportContent = generateCSVReport(scan);
        fileName = `scan-report-${scanId}.csv`;
        contentType = 'text/csv';
        break;
      case 'html':
      default:
        reportContent = generateHTMLReport(scan);
        fileName = `scan-report-${scanId}.html`;
        contentType = 'text/html';
        break;
    }

    // Upload to storage
    const filePath = `${user.id}/${fileName}`;
    const { error: uploadError } = await supabaseClient.storage
      .from('scan-reports')
      .upload(filePath, new Blob([reportContent], { type: contentType }), {
        cacheControl: '3600',
        upsert: true,
      });

    if (uploadError) {
      throw new Error('Failed to save report');
    }

    // Create report record
    const { data: report, error: reportError } = await supabaseClient
      .from('scan_reports')
      .insert({
        scan_id: scanId,
        user_id: user.id,
        format: format,
        file_path: filePath,
        file_size: reportContent.length,
      })
      .select()
      .single();

    if (reportError) {
      throw new Error('Failed to create report record');
    }

    // SECURITY FIX: Use signed URL with expiration instead of public URL
    const { data: { signedUrl }, error: signError } = await supabaseClient.storage
      .from('scan-reports')
      .createSignedUrl(filePath, 3600); // 1 hour expiration

    if (signError || !signedUrl) {
      throw new Error('Failed to generate download link');
    }

    return new Response(
      JSON.stringify({
        reportId: report.id,
        downloadUrl: signedUrl,
        fileName: fileName,
        format: format,
        size: reportContent.length,
      }),
      {
        headers: corsHeaders,
      }
    );
  } catch (error) {
    console.error('Error');
    return new Response(
      JSON.stringify({ error: 'Failed to generate report' }),
      {
        status: 500,
        headers: corsHeaders,
      }
    );
  }
});

function generateHTMLReport(scan: any): string {
  const findings = scan.findings || [];
  const highRisk = findings.filter((f: any) => f.severity === 'High').length;
  const mediumRisk = findings.filter((f: any) => f.severity === 'Medium').length;
  const lowRisk = findings.filter((f: any) => f.severity === 'Low').length;

  return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Scan Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { text-align: center; border-bottom: 2px solid #e0e0e0; padding-bottom: 20px; margin-bottom: 30px; }
        .logo { font-size: 24px; font-weight: bold; color: #2563eb; margin-bottom: 10px; }
        .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-card.high { background: linear-gradient(135deg, #ff6b6b 0%, #ee5a24 100%); }
        .stat-card.medium { background: linear-gradient(135deg, #feca57 0%, #ff9ff3 100%); }
        .stat-card.low { background: linear-gradient(135deg, #48dbfb 0%, #0abde3 100%); }
        .stat-number { font-size: 36px; font-weight: bold; margin-bottom: 5px; }
        .stat-label { font-size: 14px; opacity: 0.9; }
        .findings { margin-top: 30px; }
        .finding { background: white; border: 1px solid #e0e0e0; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
        .finding-header { padding: 15px 20px; background: #f8f9fa; border-bottom: 1px solid #e0e0e0; }
        .finding-title { font-size: 18px; font-weight: bold; margin-bottom: 5px; }
        .finding-meta { display: flex; gap: 10px; align-items: center; font-size: 14px; color: #666; }
        .severity { padding: 4px 12px; border-radius: 20px; font-weight: bold; font-size: 12px; }
        .severity.High { background: #fee; color: #c53030; }
        .severity.Medium { background: #fffaf0; color: #d69e2e; }
        .severity.Low { background: #f0fff4; color: #38a169; }
        .finding-body { padding: 20px; }
        .section { margin-bottom: 15px; }
        .section h4 { margin: 0 0 8px 0; color: #333; }
        .section p { margin: 0; color: #666; line-height: 1.5; word-break: break-word; }
        .url-box { background: #f1f5f9; padding: 10px; border-radius: 4px; font-family: monospace; word-break: break-all; white-space: pre-wrap; }
        .footer { margin-top: 40px; padding-top: 20px; border-top: 1px solid #e0e0e0; text-align: center; color: #666; font-size: 14px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">🛡️ OWASP Security Scanner</div>
            <h1>Security Scan Report</h1>
            <p><strong>Target:</strong> <code>${escapeHtml(scan.target_url)}</code></p>
            <p><strong>Scan Date:</strong> ${new Date(scan.started_at).toLocaleString()}</p>
            <p><strong>Status:</strong> ${escapeHtml(scan.status.toUpperCase())}</p>
        </div>

        <div class="summary">
            <div class="stat-card">
                <div class="stat-number">${findings.length}</div>
                <div class="stat-label">Total Findings</div>
            </div>
            <div class="stat-card high">
                <div class="stat-number">${highRisk}</div>
                <div class="stat-label">High Risk</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-number">${mediumRisk}</div>
                <div class="stat-label">Medium Risk</div>
            </div>
            <div class="stat-card low">
                <div class="stat-number">${lowRisk}</div>
                <div class="stat-label">Low Risk</div>
            </div>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
            ${findings.map((finding: any) => `
                <div class="finding">
                    <div class="finding-header">
                        <div class="finding-title">${escapeHtml(finding.title)}</div>
                        <div class="finding-meta">
                            <span class="severity ${finding.severity}">${escapeHtml(finding.severity)}</span>
                            <span>OWASP: ${escapeHtml(finding.owasp_category)}</span>
                            <span>Tool: ${escapeHtml(finding.tool.toUpperCase())}</span>
                            ${finding.cwe_id ? `<span>CWE: ${escapeHtml(finding.cwe_id)}</span>` : ''}
                            ${finding.cvss_score ? `<span>CVSS: ${escapeHtml(finding.cvss_score.toString())}</span>` : ''}
                        </div>
                    </div>
                    <div class="finding-body">
                        <div class="section">
                            <h4>Description</h4>
                            <p>${escapeHtml(finding.description)}</p>
                        </div>
                        ${finding.affected_url ? `
                            <div class="section">
                                <h4>Affected URL</h4>
                                <div class="url-box">${escapeHtml(finding.affected_url)}</div>
                            </div>
                        ` : ''}
                        ${finding.evidence ? `
                            <div class="section">
                                <h4>Evidence</h4>
                                <p>${escapeHtml(finding.evidence)}</p>
                            </div>
                        ` : ''}
                        ${finding.recommendation ? `
                            <div class="section">
                                <h4>Recommendation</h4>
                                <p>${escapeHtml(finding.recommendation)}</p>
                            </div>
                        ` : ''}
                    </div>
                </div>
            `).join('')}
        </div>

        <div class="footer">
            <p>Generated by OWASP Security Scanner on ${new Date().toLocaleString()}</p>
            <p>This report contains confidential security information. Handle with care.</p>
        </div>
    </div>
</body>
</html>`;
}

function escapeCsvField(field: any): string {
  if (!field) return '';
  const str = field.toString();
  // SECURITY FIX: Properly escape CSV fields - quote and escape internal quotes
  if (str.includes(',') || str.includes('"') || str.includes('\n')) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return `"${str}"`;
}

function generateCSVReport(scan: any): string {
  const findings = scan.findings || [];
  const headers = [
    'Title',
    'Severity',
    'OWASP Category',
    'Tool',
    'Affected URL',
    'Description',
    'CWE ID',
    'CVSS Score',
    'Found At'
  ];

  const csvContent = [
    headers.join(','),
    ...findings.map((finding: any) => [
      escapeCsvField(finding.title),
      escapeCsvField(finding.severity),
      escapeCsvField(finding.owasp_category),
      escapeCsvField(finding.tool),
      escapeCsvField(finding.affected_url || ''),
      escapeCsvField(finding.description || ''),
      escapeCsvField(finding.cwe_id || ''),
      escapeCsvField(finding.cvss_score || ''),
      new Date(finding.created_at).toISOString()
    ].join(','))
  ].join('\n');

  return csvContent;
}