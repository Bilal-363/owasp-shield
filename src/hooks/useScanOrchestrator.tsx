import { useState, useEffect, useRef, createContext, useContext } from "react";
import { supabase } from "@/integrations/supabase/client";
import { useAuth } from "./useAuth";
import { useToast } from "./use-toast";

export interface ScanData {
  id: string;
  target_url: string;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  tools_used: string[];
  started_at: string;
  completed_at?: string;
  total_findings: number;
  high_risk_findings: number;
  medium_risk_findings: number;
  low_risk_findings: number;
  error_message?: string;
}

export interface ScanLog {
  id: string;
  scan_id: string;
  message: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  timestamp: string;
}

export interface Finding {
  id: string;
  scan_id: string;
  tool: string;
  owasp_category: string;
  severity: 'High' | 'Medium' | 'Low' | 'Info';
  title: string;
  description?: string;
  evidence?: string;
  recommendation?: string;
  affected_url?: string;
  parameters?: string[];
  cwe_id?: string;
  cvss_score?: number;
  created_at: string;
}

interface ScanOrchestratorContextType {
  currentScan: ScanData | null;
  scanLogs: ScanLog[];
  findings: Finding[];
  loading: boolean;
  startScan: (targetUrl: string, tools: string[], scanConfig?: any) => Promise<string | null>;
  stopScan: (scanId: string) => Promise<void>;
  getScanHistory: () => Promise<any[]>;
  getScanDetails: (scanId: string) => Promise<any>;
  generateReport: (scanId: string, format: 'html' | 'json' | 'csv' | 'doc') => Promise<any>;
}

const ScanOrchestratorContext = createContext<ScanOrchestratorContextType | undefined>(undefined);

export const ScanOrchestratorProvider = ({ children }: { children: React.ReactNode }) => {
  const { session } = useAuth();
  const { toast } = useToast();
  const [currentScan, setCurrentScan] = useState<ScanData | null>(null);
  const [scanLogs, setScanLogs] = useState<ScanLog[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(false);

  const currentScanIdRef = useRef<string | null>(null);

  useEffect(() => {
    currentScanIdRef.current = currentScan?.id || null;
  }, [currentScan?.id]);

  // Set up real-time subscriptions
  useEffect(() => {
    if (!session?.user) return;

    // Subscribe to scan updates
    const scanSubscription = supabase
      .channel('scan-updates')
      .on(
        'postgres_changes',
        {
          event: '*',
          schema: 'public',
          table: 'scans',
          filter: `user_id=eq.${session.user.id}`,
        },
        (payload) => {
          console.log('Scan update:', payload);
          if (payload.new) {
            setCurrentScan(payload.new as any);
          }
        }
      )
      .subscribe();

    // Subscribe to scan logs
    const logsSubscription = supabase
      .channel('scan-logs')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'scan_logs',
        },
        (payload) => {
          console.log('New scan log:', payload);
          if (payload.new && currentScanIdRef.current === payload.new.scan_id) {
            setScanLogs(prev => {
              if (prev.some(l => l.id === payload.new.id)) return prev;
              return [...prev, payload.new as ScanLog];
            });
          }
        }
      )
      .subscribe();

    // Subscribe to findings
    const findingsSubscription = supabase
      .channel('scan-findings')
      .on(
        'postgres_changes',
        {
          event: 'INSERT',
          schema: 'public',
          table: 'findings',
        },
        (payload) => {
          console.log('New finding:', payload);
          if (payload.new && currentScanIdRef.current === payload.new.scan_id) {
            setFindings(prev => {
              if (prev.some(f => f.id === payload.new.id)) return prev;
              return [...prev, payload.new as Finding];
            });
          }
        }
      )
      .subscribe();

    return () => {
      scanSubscription.unsubscribe();
      logsSubscription.unsubscribe();
      findingsSubscription.unsubscribe();
    };
  }, [session?.user]);

  // Load existing logs and findings when currentScan changes, and poll if running/pending
  useEffect(() => {
    if (!session?.user || !currentScan?.id) return;

    let intervalId: any;

    const fetchExistingData = async () => {
      try {
        // Fetch current scan status from DB to ensure sync
        const { data: latestScan, error: scanError } = await supabase
          .from('scans')
          .select('*')
          .eq('id', currentScan.id)
          .single();

        if (scanError) throw scanError;
        if (latestScan) {
          setCurrentScan(latestScan as ScanData);
        }

        const { data: existingLogs, error: logsError } = await supabase
          .from('scan_logs')
          .select('*')
          .eq('scan_id', currentScan.id)
          .order('timestamp', { ascending: true });

        if (logsError) throw logsError;
        setScanLogs((existingLogs || []) as ScanLog[]);

        const { data: existingFindings, error: findingsError } = await supabase
          .from('findings')
          .select('*')
          .eq('scan_id', currentScan.id)
          .order('created_at', { ascending: true });

        if (findingsError) throw findingsError;
        setFindings((existingFindings || []) as Finding[]);

        // If the scan is no longer running, stop polling
        if (latestScan && latestScan.status !== 'running' && latestScan.status !== 'pending') {
          clearInterval(intervalId);
        }
      } catch (err) {
        console.error("Error fetching/polling scan details:", err);
      }
    };

    // Run immediately
    fetchExistingData();

    // If status is 'running' or 'pending', set up polling every 1.5 seconds as a robust fallback to Realtime
    if (currentScan.status === 'running' || currentScan.status === 'pending') {
      intervalId = setInterval(fetchExistingData, 1500);
    }

    return () => {
      if (intervalId) clearInterval(intervalId);
    };
  }, [session?.user, currentScan?.id, currentScan?.status]);

  const runClientSideSimulation = async (scan: ScanData) => {
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

    const addLog = async (msg: string, lvl: 'info' | 'warning' | 'error' = 'info') => {
      await supabase.from('scan_logs').insert({
        scan_id: scan.id,
        message: msg,
        level: lvl,
      });
    };

    const addFinding = async (finding: any) => {
      await supabase.from('findings').insert({
        scan_id: scan.id,
        ...finding,
      });
    };

    try {
      await addLog(`Starting security scan`, 'info');
      await addLog(`Selected tools: ${scan.tools_used.join(", ")}`, 'info');

      for (let i = 0; i < scanSteps.length; i++) {
        // Sleep 2 seconds
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Double check if the scan has been cancelled
        const { data: latestScan } = await supabase
          .from('scans')
          .select('status')
          .eq('id', scan.id)
          .single();
          
        if (latestScan?.status === 'cancelled') {
          console.log("Scan cancelled by user, stopping simulation.");
          return;
        }

        await addLog(scanSteps[i], 'info');

        // Add some realistic findings
        if (i === 1 && scan.tools_used.includes("subfinder")) {
          await addLog("Subfinder: Scanning for subdomains...", 'warning');
          await addFinding({
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
          await addLog("Gobuster: Scanning directories...", 'warning');
          await addFinding({
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

        if (i === 2 && scan.tools_used.includes("sqlmap")) {
          await addLog("SQLMap: Testing for SQL injection...", 'warning');
          await addFinding({
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
        
        if (i === 3 && scan.tools_used.includes("zap")) {
          await addLog("ZAP: Found potential authentication bypass in /admin", 'error');
          await addFinding({
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
          await addLog("Wapiti: Checking form parameters...", 'warning');
          await addFinding({
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
          await addLog("Nuclei: Running template-based security checks...", 'warning');
          await addFinding({
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
          await addLog("Hydra: Performing login security verification...", 'warning');
          await addFinding({
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
          await addLog("Retire.js: Analyzing client-side JavaScript libraries...", 'warning');
          await addFinding({
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
          await addLog("ffuf: Fuzzing parameter injection endpoints...", 'warning');
          await addFinding({
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

        if (i === 6 && scan.tools_used.includes("nikto")) {
          await addLog("Nikto: Detected outdated server version", 'warning');
          await addFinding({
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
          await addLog("XSStrike: Testing parameters for XSS...", 'warning');
          await addFinding({
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
          await addLog("Dalfox: Automated parameter verification...", 'warning');
          await addFinding({
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
          await addLog("testssl.sh: Auditing SSL/TLS settings...", 'warning');
          await addFinding({
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
          await addLog("SecurityHeaders.com: Checking security headers...", 'warning');
          await addFinding({
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
          await addLog("WPScan: Scanning WordPress metadata...", 'warning');
          await addFinding({
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
          await addLog("Nmap: Scanning port ranges...", 'warning');
          await addFinding({
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
          await addLog("Metasploit: Verifying exploitable vulnerability vectors...", 'warning');
          await addFinding({
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

        // Update progress
        const progress = Math.round(((i + 1) / scanSteps.length) * 100);
        await supabase
          .from('scans')
          .update({ 
            status: progress === 100 ? 'completed' : 'running',
            completed_at: progress === 100 ? new Date().toISOString() : null
          })
          .eq('id', scan.id);
      }

      // Fetch findings to update statistics
      const { data: findingsList } = await supabase
        .from('findings')
        .select('severity')
        .eq('scan_id', scan.id);

      const stats = (findingsList || []).reduce((acc: any, f: any) => {
        acc.total_findings++;
        if (f.severity === 'High') acc.high_risk_findings++;
        else if (f.severity === 'Medium') acc.medium_risk_findings++;
        else if (f.severity === 'Low') acc.low_risk_findings++;
        return acc;
      }, { total_findings: 0, high_risk_findings: 0, medium_risk_findings: 0, low_risk_findings: 0 });

      await supabase
        .from('scans')
        .update(stats)
        .eq('id', scan.id);

      await addLog("Security scan completed successfully!", 'info');
    } catch (simError) {
      console.error("Simulation error:", simError);
      await supabase
        .from('scans')
        .update({
          status: 'failed',
          error_message: (simError as any).message || "Simulation error",
          completed_at: new Date().toISOString()
        })
        .eq('id', scan.id);
      await addLog(`Scan failed: ${(simError as any).message}`, 'error');
    }
  };

  const startScan = async (targetUrl: string, tools: string[], scanConfig: any = {}) => {
    if (!session?.access_token) {
      toast({
        title: "Authentication Required",
        description: "Please sign in to start a scan.",
        variant: "destructive",
      });
      return null;
    }

    setLoading(true);
    setScanLogs([]);
    setFindings([]);

    try {
      let scanId: string;
      let scanData: ScanData;

      try {
        const response = await supabase.functions.invoke('scan-orchestrator', {
          body: {
            action: 'start',
            targetUrl,
            tools,
            scanConfig,
          },
        });

        if (response.error) {
          throw response.error;
        }

        scanId = response.data.scanId;
        
        // Fetch initial scan data
        const { data, error: scanError } = await supabase
          .from('scans')
          .select('*')
          .eq('id', scanId)
          .single();

        if (scanError) throw scanError;
        scanData = data as ScanData;

        toast({
          title: "Scan Started",
          description: `Security scan initiated for ${targetUrl}`,
        });
      } catch (invokeError) {
        console.warn("Edge function invocation failed, falling back to client-side simulated scan:", invokeError);
        
        // SECURITY FIX: Disable client-side database fallback writes in production
        if (!import.meta.env.DEV) {
          throw new Error("Local simulated fallback is disabled in production. Please check Edge Function status.");
        }
        
        // Directly insert the scan into the DB
        const { data, error: insertError } = await supabase
          .from('scans')
          .insert({
            user_id: session.user.id,
            target_url: targetUrl,
            status: 'running',
            tools_used: tools,
            scan_config: scanConfig,
            started_at: new Date().toISOString(),
          })
          .select()
          .single();

        if (insertError) throw insertError;
        scanData = data as ScanData;
        scanId = scanData.id;

        setCurrentScan(scanData);
        currentScanIdRef.current = scanId;

        // Run client-side simulation
        runClientSideSimulation(scanData);
        
        toast({
          title: "Local Scan Started (Fallback)",
          description: `Initiated simulated scan for ${targetUrl} (Edge Function offline)`,
        });
      }

      setCurrentScan(scanData);
      currentScanIdRef.current = scanId;
      return scanId;
    } catch (error: any) {
      console.error('Start scan error:', error);
      toast({
        title: "Scan Failed",
        description: error.message || "Failed to start security scan",
        variant: "destructive",
      });
      return null;
    } finally {
      setLoading(false);
    }
  };

  const stopScan = async (scanId: string) => {
    if (!session?.access_token) return;

    try {
      let stopped = false;
      try {
        const response = await supabase.functions.invoke('scan-orchestrator', {
          body: {
            action: 'stop',
            scanId,
          },
        });

        if (response.error) {
          throw response.error;
        }
        stopped = true;
      } catch (invokeError) {
        console.warn("Edge function stopScan failed, running client-side stop:", invokeError);
        
        // Try directly updating database status
        const { error } = await supabase
          .from('scans')
          .update({ 
            status: 'cancelled',
            completed_at: new Date().toISOString()
          })
          .eq('id', scanId)
          .eq('user_id', session.user.id);

        if (error) throw error;
        
        await supabase.from('scan_logs').insert({
          scan_id: scanId,
          message: "Scan stopped by user",
          level: 'info',
        });
        stopped = true;
      }

      if (stopped) {
        toast({
          title: "Scan Stopped",
          description: "Security scan has been terminated.",
        });
      }
    } catch (error: any) {
      console.error('Stop scan error:', error);
      toast({
        title: "Error",
        description: error.message || "Failed to stop scan",
        variant: "destructive",
      });
    }
  };

  const getScanHistory = async () => {
    if (!session?.user) return [];

    try {
      const { data, error } = await supabase
        .from('scans')
        .select('*')
        .eq('user_id', session.user.id)
        .order('started_at', { ascending: false });

      if (error) throw error;
      return data || [];
    } catch (error: any) {
      console.error('Get scan history error:', error);
      return [];
    }
  };

  const getScanDetails = async (scanId: string) => {
    if (!session?.user) return null;

    try {
      const { data: scan, error: scanError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .eq('user_id', session.user.id)
        .single();

      if (scanError) throw scanError;

      const { data: findings, error: findingsError } = await supabase
        .from('findings')
        .select('*')
        .eq('scan_id', scanId)
        .order('created_at', { ascending: false });

      if (findingsError) throw findingsError;

      const { data: logs, error: logsError } = await supabase
        .from('scan_logs')
        .select('*')
        .eq('scan_id', scanId)
        .order('timestamp', { ascending: true });

      if (logsError) throw logsError;

      return {
        scan,
        findings: findings || [],
        logs: logs || [],
      };
    } catch (error: any) {
      console.error('Get scan details error:', error);
      return null;
    }
  };

  const generateReport = async (scanId: string, format: 'html' | 'json' | 'csv' = 'html') => {
    if (!session?.access_token) return null;

    try {
      let reportData = null;
      try {
        const response = await supabase.functions.invoke('report-generator', {
          body: {
            scanId,
            format,
          },
        });

        if (response.error) {
          throw response.error;
        }
        reportData = response.data;
      } catch (invokeError) {
        console.warn("Edge function generateReport failed, running client-side simulation fallback:", invokeError);
        
        // SECURITY FIX: Disable client-side database fallback writes in production
        if (!import.meta.env.DEV) {
          throw new Error("Local report generation fallback is disabled in production. Please check Edge Function status.");
        }
        
        // Simulating the report generation in the database
        const details = await getScanDetails(scanId);
        if (!details) throw new Error("Could not fetch scan details to generate report locally.");
        
        // Create scan report record
        const { data: reportRecord, error: reportError } = await supabase
          .from('scan_reports')
          .insert({
            scan_id: scanId,
            user_id: session.user.id,
            format,
            file_size: 1024, // Mock size
          })
          .select()
          .single();

        if (reportError) throw reportError;
        
        reportData = {
          reportId: reportRecord.id,
          message: "Local report generated",
        };
      }

      toast({
        title: "Report Generated",
        description: `${format.toUpperCase()} report has been generated successfully.`,
      });

      return reportData;
    } catch (error: any) {
      console.error('Generate report error:', error);
      toast({
        title: "Report Generation Failed",
        description: error.message || "Failed to generate report",
        variant: "destructive",
      });
      return null;
    }
  };

  return (
    <ScanOrchestratorContext.Provider value={{
      currentScan,
      scanLogs,
      findings,
      loading,
      startScan,
      stopScan,
      getScanHistory,
      getScanDetails,
      generateReport,
    }}>
      {children}
    </ScanOrchestratorContext.Provider>
  );
};

export const useScanOrchestrator = () => {
  const context = useContext(ScanOrchestratorContext);
  if (!context) {
    throw new Error("useScanOrchestrator must be used within a ScanOrchestratorProvider");
  }
  return context;
};