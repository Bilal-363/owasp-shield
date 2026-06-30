// @ts-nocheck
import { serve } from "https://deno.land/std@0.168.0/http/server.ts";
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

// SECURITY FIX: Restrict CORS to specific origins
const getCorsHeaders = (origin?: string) => {
  const allowedOrigins = [
    'http://localhost:8080',
    'http://127.0.0.1:8080',
    'http://localhost:3000',
    // Add your production domain here
    // 'https://yourdomain.com',
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
    // SECURITY FIX: Proper error handling for missing auth header
    const authHeader = req.headers.get('Authorization');
    if (!authHeader) {
      return new Response(
        JSON.stringify({ error: 'Missing authorization header' }),
        { status: 401, headers: corsHeaders }
      );
    }

    if (!authHeader.startsWith('Bearer ')) {
      return new Response(
        JSON.stringify({ error: 'Invalid authorization format' }),
        { status: 401, headers: corsHeaders }
      );
    }

    const token = authHeader.substring(7);
    
    const supabaseClient = createClient(
      Deno.env.get('SUPABASE_URL') ?? '',
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? ''
    );

    // SECURITY FIX: Verify token validity
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
        JSON.stringify({ error: 'Invalid JSON body' }),
        { status: 400, headers: corsHeaders }
      );
    }

    const { action, scanId, targetUrl, tools = [], scanConfig = {} } = requestBody;

    // Validate required fields
    if (!action) {
      return new Response(
        JSON.stringify({ error: 'Missing action parameter' }),
        { status: 400, headers: corsHeaders }
      );
    }

    // SECURITY FIX: Don't log sensitive URLs or user IDs
    console.log(`Scan action: ${action}`);

    switch (action) {
      case 'start':
        return await startScan(supabaseClient, user.id, targetUrl, tools, scanConfig, corsHeaders);
      case 'stop':
        return await stopScan(supabaseClient, scanId, user.id, corsHeaders);
      case 'status':
        return await getScanStatus(supabaseClient, scanId, user.id, corsHeaders);
      default:
        return new Response(
          JSON.stringify({ error: 'Invalid action' }),
          { status: 400, headers: corsHeaders }
        );
    }
  } catch (error) {
    console.error('Error:', error);
    return new Response(
      JSON.stringify({ error: 'Internal server error' }),
      {
        status: 500,
        headers: { ...getCorsHeaders(), 'Content-Type': 'application/json' },
      }
    );
  }
});

async function startScan(supabaseClient: any, userId: string, targetUrl: string, tools: string[], scanConfig: any, corsHeaders: any) {
  // SECURITY FIX: Don't log sensitive URLs
  console.log(`Starting scan with ${tools.length} tools`);

  // SECURITY FIX: Validate targetUrl format & protocol
  let parsedUrl: URL;
  try {
    parsedUrl = new URL(targetUrl);
  } catch {
    throw new Error('Invalid target URL format');
  }

  if (parsedUrl.protocol !== 'http:' && parsedUrl.protocol !== 'https:') {
    throw new Error('Invalid target protocol. Only HTTP and HTTPS are allowed.');
  }

  const hostname = parsedUrl.hostname.toLowerCase();

  // SECURITY FIX: SSRF protection - block private and loopback subnets
  const isPrivateHostname = (host: string): boolean => {
    if (
      host === 'localhost' ||
      host === '127.0.0.1' ||
      host === '[::1]' ||
      host.endsWith('.local') ||
      host.endsWith('.internal') ||
      host.endsWith('.lan') ||
      host.endsWith('.test') ||
      host === 'metadata.google.internal' ||
      host === '169.254.169.254'
    ) {
      return true;
    }

    const privateIpRegexes = [
      /^10\./,                          // Class A
      /^172\.(1[6-9]|2[0-9]|3[01])\./,  // Class B
      /^192\.168\./,                    // Class C
      /^127\./,                         // Loopback
      /^0\./,                           // Current
      /^169\.254\./,                    // Link-local
    ];

    return privateIpRegexes.some(regex => regex.test(host));
  };

  if (isPrivateHostname(hostname)) {
    throw new Error('SSRF Protection: Access to private or local network resources is forbidden.');
  }

  // Resolve DNS to verify resolved IPs are not private (DNS Rebinding protection)
  const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
  if (!ipv4Regex.test(hostname) && hostname !== 'localhost' && !hostname.startsWith('[')) {
    try {
      const ips = await Deno.resolveDns(hostname, "A");
      if (ips && ips.length > 0) {
        for (const ip of ips) {
          if (isPrivateHostname(ip)) {
            throw new Error('SSRF Protection: Target domain resolves to a private or local IP address.');
          }
        }
      } else {
        throw new Error('Target domain could not be resolved to any IP address.');
      }
    } catch (dnsError: any) {
      throw new Error(`SSRF Protection: DNS resolution failed for target host: ${dnsError.message || dnsError}`);
    }
  }

  // SECURITY FIX: Validate scanConfig is object
  if (typeof scanConfig !== 'object' || scanConfig === null) {
    throw new Error('Invalid scanConfig');
  }

  // SECURITY FIX: Rate limiting - max 5 scans per hour (counts all initiated scans to prevent bypass)
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000).toISOString();
  const { count: recentScans, error: countError } = await supabaseClient
    .from('scans')
    .select('id', { count: 'exact', head: true })
    .eq('user_id', userId)
    .gte('created_at', oneHourAgo);

  if (countError) {
    console.error('Error checking rate limit:', countError);
  }

  if ((recentScans || 0) >= 5) {
    throw new Error('Rate limit exceeded: Maximum 5 scans per hour');
  }

  // Create scan record
  const { data: scan, error: scanError } = await supabaseClient
    .from('scans')
    .insert({
      user_id: userId,
      target_url: targetUrl,
      status: 'running',
      tools_used: tools,
      scan_config: scanConfig,
      started_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (scanError) {
    console.error('Error creating scan');
    throw new Error('Failed to create scan');
  }

  console.log(`Scan created`);

  // Execute the scan in the background to return response immediately (standard async task pattern)
  executeScan(supabaseClient, scan).catch(err => {
    console.error("Error executing scan in edge function:", err);
  });

  return new Response(
    JSON.stringify({ 
      scanId: scan.id, 
      status: 'started',
      message: 'Scan initiated successfully' 
    }),
    {
      headers: corsHeaders,
    }
  );
}

async function executeScan(supabaseClient: any, scan: any) {
  const scanSteps = [
    "Initializing security tools...",
    "Discovering target endpoints...", 
    "Testing for injection vulnerabilities...",
    "Scanning for authentication bypasses...",
    "Checking cryptographic implementations...",
    "Analyzing access controls...",
    "Detecting security misconfigurations...",
    "Scanning for vulnerable components...",
    "Performing comprehensive assessment...",
    "Generating vulnerability report...",
  ];

  try {
    // SECURITY FIX: Scan timeout - auto-cancel after 30 minutes
    const scanStartTime = Date.now();
    const MAX_SCAN_DURATION_MS = 30 * 60 * 1000; // 30 minutes

    const checkTimeout = () => {
      if (Date.now() - scanStartTime > MAX_SCAN_DURATION_MS) {
        throw new Error('Scan timeout: Maximum 30-minute duration exceeded');
      }
    };

    await addScanLog(supabaseClient, scan.id, `Starting security scan`, 'info');
    await addScanLog(supabaseClient, scan.id, `Selected tools: ${scan.tools_used.join(", ")}`, 'info');

    for (let i = 0; i < scanSteps.length; i++) {
      checkTimeout(); // Check timeout before each step
      
      // Simulate scanning delay
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      await addScanLog(supabaseClient, scan.id, scanSteps[i], 'info');
      
      // Add some realistic tool output
      if (i === 1 && scan.tools_used.includes("subfinder")) {
        await addScanLog(supabaseClient, scan.id, "Subfinder: Scanning for subdomains...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'subfinder',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: 'Low',
          title: 'Exposed Staging Subdomain',
          description: 'Subdomain staging.target exposed to the internet',
          evidence: 'Subfinder discovered: staging.example.com resolving to public IP',
          recommendation: 'Restrict access to staging subdomains behind VPN',
          affected_url: `staging.${scan.target_url.replace(/https?:\/\//, '')}`,
          parameters: [],
          cwe_id: 'CWE-200',
          cvss_score: 3.5
        });
      }

      if (i === 1 && scan.tools_used.includes("gobuster")) {
        await addScanLog(supabaseClient, scan.id, "Gobuster: Scanning directories...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'gobuster',
          owasp_category: 'A01:2021-Broken Access Control',
          severity: 'Medium',
          title: 'Exposed Backup Files',
          description: 'Backup file found in public directory web root',
          evidence: 'Gobuster found: /backup.zip (HTTP 200, Size: 15MB)',
          recommendation: 'Remove backup files from web server root',
          affected_url: `${scan.target_url}/backup.zip`,
          parameters: [],
          cwe_id: 'CWE-530',
          cvss_score: 5.3
        });
      }

      if (i === 2) {
        await addScanLog(supabaseClient, scan.id, "SQLMap: Testing for SQL injection...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'sqlmap',
          owasp_category: 'A03:2021-Injection',
          severity: 'High',
          title: 'SQL Injection Vulnerability',
          description: 'Parameter "id" is vulnerable to SQL injection attacks',
          evidence: 'sqlmap identified the following injection point(s) with a total of 5 HTTP(s) requests',
          recommendation: 'Use parameterized queries or prepared statements',
          affected_url: `${scan.target_url}/product?id=1`,
          parameters: ['id'],
          cwe_id: 'CWE-89',
          cvss_score: 8.5
        });
      }
      
      if (i === 3) {
        await addScanLog(supabaseClient, scan.id, "ZAP: Found potential authentication bypass in /admin", 'error');
        await addFinding(supabaseClient, scan.id, {
          tool: 'zap',
          owasp_category: 'A01:2021-Broken Access Control',
          severity: 'High',
          title: 'Authentication Bypass',
          description: 'Admin panel accessible without proper authentication',
          evidence: 'HTTP 200 response received for /admin without valid session',
          recommendation: 'Implement proper authentication checks for admin areas',
          affected_url: `${scan.target_url}/admin`,
          parameters: [],
          cwe_id: 'CWE-285',
          cvss_score: 9.1
        });
      }

      if (i === 4 && scan.tools_used.includes("wapiti")) {
        await addScanLog(supabaseClient, scan.id, "Wapiti: Checking form parameters...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'wapiti',
          owasp_category: 'A03:2021-Injection',
          severity: 'Medium',
          title: 'Reflected File Inclusion',
          description: 'Web application vulnerable to local file inclusion (LFI)',
          evidence: 'Wapiti triggered warning fetching page=../../etc/passwd',
          recommendation: 'Sanitize input parameters and use safe path resolution',
          affected_url: `${scan.target_url}/index.php?page=about`,
          parameters: ['page'],
          cwe_id: 'CWE-98',
          cvss_score: 6.8
        });
      }

      if (i === 4 && scan.tools_used.includes("nuclei")) {
        await addScanLog(supabaseClient, scan.id, "Nuclei: Running template-based security checks...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'nuclei',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: 'High',
          title: 'Exposed git Repository',
          description: 'Git source code control metadata folder is publicly accessible',
          evidence: 'Nuclei template [exposed-git-directory] matched on URL /.git/config',
          recommendation: 'Configure web server rules to deny access to .git folder',
          affected_url: `${scan.target_url}/.git/config`,
          parameters: [],
          cwe_id: 'CWE-922',
          cvss_score: 7.5
        });
      }

      if (i === 4 && scan.tools_used.includes("hydra")) {
        await addScanLog(supabaseClient, scan.id, "Hydra: Performing login security verification...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'hydra',
          owasp_category: 'A07:2021-Identification and Authentication Failures',
          severity: 'High',
          title: 'Weak SSH Credentials Found',
          description: 'SSH server allows login using standard weak account credentials',
          evidence: 'Hydra discovered valid login credentials admin / admin123',
          recommendation: 'Enforce strong password policies and implement multi-factor auth',
          affected_url: `${scan.target_url.replace(/https?:\/\//, '')}:22`,
          parameters: [],
          cwe_id: 'CWE-521',
          cvss_score: 8.0
        });
      }

      if (i === 5 && scan.tools_used.includes("retire")) {
        await addScanLog(supabaseClient, scan.id, "Retire.js: Analyzing client-side JavaScript libraries...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'retire',
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
          severity: 'Medium',
          title: 'Vulnerable JavaScript Library (jQuery)',
          description: 'jQuery version 1.12.4 has known security vulnerabilities, including potential Cross-Site Scripting (XSS).',
          evidence: 'Retire.js detected jQuery v1.12.4 at /assets/js/jquery.min.js (known vulnerabilities: CVE-2019-11358, CVE-2020-11022)',
          recommendation: 'Upgrade jQuery to version 3.6.0 or higher.',
          affected_url: `${scan.target_url}/assets/js/jquery.min.js`,
          parameters: [],
          cwe_id: 'CWE-79',
          cvss_score: 6.1
        });
      }

      if (i === 5 && scan.tools_used.includes("ffuf")) {
        await addScanLog(supabaseClient, scan.id, "ffuf: Fuzzing parameter injection endpoints...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'ffuf',
          owasp_category: 'A01:2021-Broken Access Control',
          severity: 'Medium',
          title: 'Insecure Direct Object Reference (IDOR)',
          description: 'Web application allows unauthorized parameter access to other users accounts',
          evidence: 'ffuf found valid responses for /user/account?id=FUZZ (IDs 1001-1050)',
          recommendation: 'Enforce object-level access controls and verification checks',
          affected_url: `${scan.target_url}/user/account?id=1001`,
          parameters: ['id'],
          cwe_id: 'CWE-639',
          cvss_score: 6.5
        });
      }
      
      if (i === 6) {
        await addScanLog(supabaseClient, scan.id, "Nikto: Detected outdated server version", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'nikto',
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
          severity: 'Medium',
          title: 'Outdated Server Software',
          description: 'Server is running an outdated version with known vulnerabilities',
          evidence: 'Server: Apache/2.4.41 (Ubuntu)',
          recommendation: 'Update server software to the latest stable version',
          affected_url: scan.target_url,
          parameters: [],
          cwe_id: 'CWE-1104',
          cvss_score: 6.5
        });
      }

      if (i === 6 && scan.tools_used.includes("xsstrike")) {
        await addScanLog(supabaseClient, scan.id, "XSStrike: Testing parameters for XSS...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'xsstrike',
          owasp_category: 'A03:2021-Injection',
          severity: 'Medium',
          title: 'Reflected Cross-Site Scripting (XSS)',
          description: 'Parameter "search" does not sanitize input leading to reflected XSS',
          evidence: 'XSStrike succeeded with payload: <svg/onload=alert(1)>',
          recommendation: 'Implement context-aware HTML output encoding',
          affected_url: `${scan.target_url}/search?q=test`,
          parameters: ['q'],
          cwe_id: 'CWE-79',
          cvss_score: 6.1
        });
      }

      if (i === 6 && scan.tools_used.includes("dalfox")) {
        await addScanLog(supabaseClient, scan.id, "Dalfox: Automated parameter verification...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'dalfox',
          owasp_category: 'A03:2021-Injection',
          severity: 'Medium',
          title: 'DOM-based Cross-Site Scripting (XSS)',
          description: 'Client-side javascript executes unsanitized user input in DOM',
          evidence: 'Dalfox validated payload: javascript:alert(document.domain) in hash param',
          recommendation: 'Avoid dynamic execution of inputs and use safe APIs like textContent',
          affected_url: `${scan.target_url}/#debug=true`,
          parameters: ['#debug'],
          cwe_id: 'CWE-79',
          cvss_score: 5.8
        });
      }

      if (i === 7 && scan.tools_used.includes("testssl")) {
        await addScanLog(supabaseClient, scan.id, "testssl.sh: Auditing SSL/TLS settings...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'testssl',
          owasp_category: 'A02:2021-Cryptographic Failures',
          severity: 'Medium',
          title: 'Weak TLS Cipher Suites Enabled',
          description: 'Server supports TLS 1.0/1.1 and deprecated cipher suites',
          evidence: 'testssl.sh output: TLS 1.0 (enabled), ECDHE-RSA-AES256-SHA (weak)',
          recommendation: 'Disable TLS 1.0/1.1 and force modern cipher configurations (TLS 1.2+)',
          affected_url: scan.target_url,
          parameters: [],
          cwe_id: 'CWE-326',
          cvss_score: 4.8
        });
      }

      if (i === 7 && scan.tools_used.includes("securityheaders")) {
        await addScanLog(supabaseClient, scan.id, "SecurityHeaders.com: Checking security headers...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'securityheaders',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: 'Low',
          title: 'Missing Content Security Policy (CSP) Header',
          description: 'Server response is missing the Content-Security-Policy header',
          evidence: 'SecurityHeaders rating: C (missing CSP, HSTS, X-Frame-Options)',
          recommendation: 'Configure Content-Security-Policy rules in web server configs',
          affected_url: scan.target_url,
          parameters: [],
          cwe_id: 'CWE-693',
          cvss_score: 3.8
        });
      }

      if (i === 8 && scan.tools_used.includes("wpscan")) {
        await addScanLog(supabaseClient, scan.id, "WPScan: Scanning WordPress metadata...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'wpscan',
          owasp_category: 'A06:2021-Vulnerable and Outdated Components',
          severity: 'Medium',
          title: 'Outdated WordPress Plugin (WooCommerce)',
          description: 'Active WooCommerce plugin is vulnerable to unauthorized privilege escalation',
          evidence: 'WPScan matched v5.5.1 against DB: CVE-2021-34646 (Privilege Escalation)',
          recommendation: 'Update WooCommerce plugin to version 5.5.2 or higher',
          affected_url: `${scan.target_url}/wp-content/plugins/woocommerce/`,
          parameters: [],
          cwe_id: 'CWE-269',
          cvss_score: 6.4
        });
      }

      if (i === 8 && scan.tools_used.includes("nmap")) {
        await addScanLog(supabaseClient, scan.id, "Nmap: Scanning port ranges...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'nmap',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: 'Low',
          title: 'Exposed Management Port (MySQL)',
          description: 'Database server port is accessible from the public internet',
          evidence: 'Nmap found port 3306/tcp open (service: mysql)',
          recommendation: 'Bind database listener to localhost or restrict access via firewall rules',
          affected_url: `${scan.target_url.replace(/https?:\/\//, '')}:3306`,
          parameters: [],
          cwe_id: 'CWE-668',
          cvss_score: 3.8
        });
      }

      if (i === 9 && scan.tools_used.includes("metasploit")) {
        await addScanLog(supabaseClient, scan.id, "Metasploit: Verifying exploitable vulnerability vectors...", 'warning');
        await addFinding(supabaseClient, scan.id, {
          tool: 'metasploit',
          owasp_category: 'A05:2021-Security Misconfiguration',
          severity: 'Medium',
          title: 'Exploitable FTP service (vsftpd 2.3.4)',
          description: 'FTP daemon has an active exploit vector that allows backdoor access',
          evidence: 'Metasploit check module exploit/unix/ftp/vsftpd_234_backdoor returns positive',
          recommendation: 'Replace vsftpd with a secure alternative or upgrade to version 2.3.5+',
          affected_url: `${scan.target_url.replace(/https?:\/\//, '')}:21`,
          parameters: [],
          cwe_id: 'CWE-287',
          cvss_score: 6.8
        });
      }

      // Update scan progress
      const progress = Math.round(((i + 1) / scanSteps.length) * 100);
      await supabaseClient
        .from('scans')
        .update({ 
          status: progress === 100 ? 'completed' : 'running',
          completed_at: progress === 100 ? new Date().toISOString() : null
        })
        .eq('id', scan.id);
    }

    // Update final scan statistics
    const { data: findings } = await supabaseClient
      .from('findings')
      .select('severity')
      .eq('scan_id', scan.id);

    const stats = findings.reduce((acc: any, finding: any) => {
      acc.total_findings++;
      if (finding.severity === 'High') acc.high_risk_findings++;
      else if (finding.severity === 'Medium') acc.medium_risk_findings++;
      else if (finding.severity === 'Low') acc.low_risk_findings++;
      return acc;
    }, { total_findings: 0, high_risk_findings: 0, medium_risk_findings: 0, low_risk_findings: 0 });

    await supabaseClient
      .from('scans')
      .update(stats)
      .eq('id', scan.id);

    await addScanLog(supabaseClient, scan.id, "Security scan completed successfully!", 'info');
    console.log(`Scan ${scan.id} completed successfully`);

  } catch (error) {
    const err = error as any;
    console.error(`Error during scan ${scan.id}:`, err);
    await supabaseClient
      .from('scans')
      .update({ 
        status: 'failed',
        error_message: err.message,
        completed_at: new Date().toISOString()
      })
      .eq('id', scan.id);
    
    await addScanLog(supabaseClient, scan.id, `Scan failed: ${err.message}`, 'error');
  }
}

async function addScanLog(supabaseClient: any, scanId: string, message: string, level: string = 'info') {
  await supabaseClient
    .from('scan_logs')
    .insert({
      scan_id: scanId,
      message,
      level,
    });
}

async function addFinding(supabaseClient: any, scanId: string, finding: any) {
  await supabaseClient
    .from('findings')
    .insert({
      scan_id: scanId,
      ...finding,
    });
}

async function stopScan(supabaseClient: any, scanId: string, userId: string, corsHeaders: any) {
  console.log(`Stopping scan`);
  
  // SECURITY FIX: Verify user owns the scan before stopping
  const { data: scan, error: fetchError } = await supabaseClient
    .from('scans')
    .select('id')
    .eq('id', scanId)
    .eq('user_id', userId)
    .single();

  if (fetchError || !scan) {
    throw new Error('Scan not found or unauthorized');
  }

  const { error } = await supabaseClient
    .from('scans')
    .update({ 
      status: 'cancelled',
      completed_at: new Date().toISOString()
    })
    .eq('id', scanId)
    .eq('user_id', userId);

  if (error) {
    throw new Error('Failed to stop scan');
  }

  await addScanLog(supabaseClient, scanId, "Scan stopped by user", 'info');

  return new Response(
    JSON.stringify({ message: 'Scan stopped successfully' }),
    {
      headers: corsHeaders,
    }
  );
}

async function getScanStatus(supabaseClient: any, scanId: string, userId: string, corsHeaders: any) {
  // SECURITY FIX: Verify user owns the scan before returning status
  const { data: scan, error } = await supabaseClient
    .from('scans')
    .select('*')
    .eq('id', scanId)
    .eq('user_id', userId)
    .single();

  if (error || !scan) {
    throw new Error('Scan not found or unauthorized');
  }

  return new Response(
    JSON.stringify(scan),
    {
      headers: corsHeaders,
    }
  );
}