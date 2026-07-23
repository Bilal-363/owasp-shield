import { useState, useEffect, useRef, createContext, useContext } from "react";
import { supabase } from "@/integrations/supabase/client";
import { scannerApi } from "@/lib/scannerApi";
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
  critical_findings?: number;
  high_risk_findings: number;
  medium_risk_findings: number;
  low_risk_findings: number;
  error_message?: string;
  scan_config?: {
    current_step?: number;
    total_steps?: number;
    pinned_ip?: string;
  };
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
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
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
  startScan: (targetUrl: string, tools: string[], profile?: 'quick' | 'deep') => Promise<string | null>;
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

  // Load active running scan on mount or session change
  useEffect(() => {
    if (!session?.user) return;

    const loadActiveScan = async () => {
      try {
        const { data: activeScan } = await supabase
          .from('scans')
          .select('*')
          .eq('user_id', session.user.id)
          .in('status', ['running', 'pending'])
          .order('started_at', { ascending: false })
          .limit(1)
          .maybeSingle();

        if (activeScan) {
          setCurrentScan(activeScan as ScanData);
          currentScanIdRef.current = activeScan.id;
          await refreshScanData(activeScan.id);
        }
      } catch (err) {
        console.error("Error loading active scan:", err);
      }
    };

    loadActiveScan();
  }, [session?.user]);

  // Set up real-time subscriptions for live updates
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
            if (!currentScanIdRef.current || currentScanIdRef.current === (payload.new as any).id) {
              setCurrentScan(payload.new as any);
            }
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


  // ========================================================================
  // The REAL scan runs on the backend and streams results into Supabase.
  // The realtime subscriptions above update currentScan/logs/findings live.
  // This effect just does a safety refresh when a scan finishes and clears
  // the loading state. (No fake client-side stepping / fabricated findings.)
  // ========================================================================
  useEffect(() => {
    if (!currentScan?.id) return;
    if (
      currentScan.status === 'completed' ||
      currentScan.status === 'failed' ||
      currentScan.status === 'cancelled'
    ) {
      refreshScanData(currentScan.id);
    }
  }, [currentScan?.id, currentScan?.status]);

  // ========================================================================
  // Fallback POLLING: Supabase Realtime may not be enabled on every project,
  // so while a scan is running we also poll the DB every 2.5s to keep progress,
  // logs and findings live. (Realtime, when on, updates instantly; this just
  // guarantees the UI never gets stuck.)
  // ========================================================================
  useEffect(() => {
    if (!currentScan?.id || currentScan.status !== 'running') return;
    const scanId = currentScan.id;
    const interval = setInterval(() => {
      refreshScanData(scanId);
    }, 2500);
    return () => clearInterval(interval);
  }, [currentScan?.id, currentScan?.status]);

  // Refresh scan data, logs, and findings from database
  const refreshScanData = async (scanId: string) => {
    try {
      const { data: latestScan, error: scanError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .single();

      if (scanError) throw scanError;
      if (latestScan) {
        setCurrentScan(latestScan as ScanData);
      }

      const { data: existingLogs, error: logsError } = await supabase
        .from('scan_logs')
        .select('*')
        .eq('scan_id', scanId)
        .order('timestamp', { ascending: true });

      if (logsError) throw logsError;
      setScanLogs((existingLogs || []) as ScanLog[]);

      const { data: existingFindings, error: findingsError } = await supabase
        .from('findings')
        .select('*')
        .eq('scan_id', scanId)
        .order('created_at', { ascending: true });

      if (findingsError) throw findingsError;
      setFindings((existingFindings || []) as Finding[]);
    } catch (err) {
      console.error("Error refreshing scan data:", err);
    }
  };

  // ========================================================================
  // Start a REAL scan on the backend. The backend validates the target,
  // enforces rate limits, runs genuine checks, and streams findings/logs
  // into Supabase — which the realtime subscriptions above render live.
  // ========================================================================
  const startScan = async (targetUrl: string, tools: string[], profile: 'quick' | 'deep' = 'quick') => {
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
      const { scanId } = await scannerApi.startScan(targetUrl, tools, profile);

      // Fetch the freshly-created scan row (read-only, allowed by RLS).
      const { data, error: scanError } = await supabase
        .from('scans')
        .select('*')
        .eq('id', scanId)
        .single();

      if (scanError) throw scanError;

      setCurrentScan(data as ScanData);
      currentScanIdRef.current = scanId;

      toast({
        title: "Scan Started",
        description: `Live security scan running against ${targetUrl}`,
      });

      return scanId;
    } catch (error: any) {
      console.error('Start scan error:', error);
      toast({
        title: "Scan Failed",
        description:
          error.message ||
          "Could not reach the scanner backend. Is it running (npm start in scanner-backend)?",
        variant: "destructive",
      });
      return null;
    } finally {
      setLoading(false);
    }
  };

  // ========================================================================
  // Stop scan — asks the backend to cancel; the running scan checks for this.
  // ========================================================================
  const stopScan = async (scanId: string) => {
    if (!session?.access_token) return;

    try {
      await scannerApi.stopScan(scanId);
      await refreshScanData(scanId);

      toast({
        title: "Scan Stopped",
        description: "Security scan has been cancelled.",
      });
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

  const generateReport = async (scanId: string, format: 'html' | 'json' | 'csv' | 'doc' = 'html') => {
    if (!session?.access_token) return null;

    try {
      const response = await supabase.functions.invoke('report-generator', {
        body: {
          scanId,
          format,
        },
      });

      if (response.error) {
        throw new Error(response.error.message || 'Report generation failed');
      }

      toast({
        title: "Report Generated",
        description: `${format.toUpperCase()} report has been generated successfully.`,
      });

      return response.data;
    } catch (error: any) {
      console.error('Generate report error:', error);
      toast({
        title: "Report Generation Failed",
        description: error.message || "Failed to generate report. Please ensure the Edge Function is deployed.",
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
