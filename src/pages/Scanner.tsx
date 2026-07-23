import { useState, useEffect } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Play,
  Square,
  Scan,
  AlertTriangle,
  CheckCircle,
  Clock,
  Globe,
  Database,
  Search,
  Zap,
  AlertCircle,
  Server,
  Link,
  FolderSearch,
  Cpu,
  KeyRound,
  Terminal,
  Bug,
  Sparkles,
  Fingerprint,
  Shield,
  ShieldAlert,
  FileCode,
  Skull
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { useScanOrchestrator } from "@/hooks/useScanOrchestrator";
import { cn } from "@/lib/utils";
import { validateScanForm } from "../lib/validation";

// URL Validation - SSRF Protection
const isValidPublicUrl = (urlString: string): boolean => {
  try {
    const url = new URL(urlString);
    const hostname = url.hostname.toLowerCase();

    // Block private/internal IPs and protocols
    const blockedPatterns = [
      /^localhost$/i,
      /^127\./,
      /^192\.168\./,
      /^10\./,
      /^172\.(1[6-9]|2[0-9]|3[01])\./,
      /^::1$/,
      /^fc00:/i,
      /^fe80:/i,
    ];

    // Block file protocol
    if (url.protocol !== 'http:' && url.protocol !== 'https:') {
      return false;
    }

    // Check against blocked patterns
    if (blockedPatterns.some(pattern => pattern.test(hostname))) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
};

// Only tools the real backend actually runs. Built-in checks (retire,
// securityheaders, subfinder) always work; the rest run when installed
// (Docker image) and are skipped gracefully otherwise.
const tools = [
  { id: "nmap", name: "Nmap", description: "Port Scanner & Service Detector", icon: Server, enabled: true, category: "Recon" },
  { id: "subfinder", name: "Subfinder", description: "Subdomain Discovery", icon: Link, enabled: true, category: "Recon" },
  { id: "gobuster", name: "Gobuster", description: "Directory & File Discovery", icon: FolderSearch, enabled: true, category: "Recon" },
  { id: "ffuf", name: "ffuf", description: "Endpoint Fuzzer", icon: Terminal, enabled: true, category: "Recon" },
  { id: "whatweb", name: "WhatWeb", description: "Technology Fingerprinting", icon: Fingerprint, enabled: true, category: "Recon" },
  { id: "nuclei", name: "Nuclei", description: "Template-based CVE Scanner", icon: Cpu, enabled: true, category: "Vulnerability" },
  { id: "nikto", name: "Nikto", description: "Web Server Scanner", icon: Globe, enabled: true, category: "Web" },
  { id: "retire", name: "Retire.js", description: "Outdated JS Libraries", icon: Search, enabled: true, category: "Web" },
  { id: "sqlmap", name: "SQLMap", description: "SQL Injection Testing", icon: Database, enabled: true, category: "Injection" },
  { id: "dalfox", name: "Dalfox", description: "XSS Testing", icon: Sparkles, enabled: true, category: "Injection" },
  { id: "testssl", name: "sslscan", description: "SSL/TLS Configuration Audit", icon: ShieldAlert, enabled: true, category: "SSL" },
  { id: "securityheaders", name: "Security Headers", description: "HTTP Security Header Check", icon: Shield, enabled: true, category: "SSL" },
  { id: "wpscan", name: "WPScan", description: "WordPress Security Scanner", icon: Cpu, enabled: true, category: "CMS" },
];

export default function Scanner() {
  const [targetUrl, setTargetUrl] = useState(() => {
    return localStorage.getItem("owasp_shield_scanner_target_url") || "";
  });
  const [selectedTools, setSelectedTools] = useState<string[]>(() => {
    const savedSelected = localStorage.getItem("owasp_shield_scanner_selected_tools");
    if (savedSelected) {
      try {
        return JSON.parse(savedSelected);
      } catch (e) {
        console.error("Error parsing saved scanner tools:", e);
      }
    }
    const savedSettingsTools = localStorage.getItem("owasp_shield_settings_tools");
    if (savedSettingsTools) {
      try {
        const parsed = JSON.parse(savedSettingsTools);
        return parsed.filter((t: any) => t.settings?.enabled).map((t: any) => t.id);
      } catch (e) {
        console.error("Error parsing saved settings tools:", e);
      }
    }
    return tools.filter(t => t.enabled).map(t => t.id);
  });
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const [scanProfile, setScanProfile] = useState<'quick' | 'deep'>(() => {
    return (localStorage.getItem("owasp_shield_scan_profile") as 'quick' | 'deep') || 'quick';
  });
  const { toast } = useToast();
  const {
    currentScan,
    scanLogs,
    findings,
    loading,
    startScan,
    stopScan
  } = useScanOrchestrator();

  // Save targetUrl when changed
  useEffect(() => {
    if (targetUrl) {
      localStorage.setItem("owasp_shield_scanner_target_url", targetUrl);
    }
  }, [targetUrl]);

  // Persist chosen scan profile
  useEffect(() => {
    localStorage.setItem("owasp_shield_scan_profile", scanProfile);
  }, [scanProfile]);

  // Save selectedTools when changed
  useEffect(() => {
    localStorage.setItem("owasp_shield_scanner_selected_tools", JSON.stringify(selectedTools));
  }, [selectedTools]);

  useEffect(() => {
    if (currentScan?.target_url && !targetUrl) {
      setTargetUrl(currentScan.target_url);
    }
  }, [currentScan?.target_url, targetUrl]);

  // Real progress driven by the backend (scan_config.current_step / total_steps).
  const getScanProgress = (scan: any) => {
    if (!scan) return 0;
    const { status } = scan;
    if (status === 'completed' || status === 'failed' || status === 'cancelled') return 100;
    if (status === 'pending') return 0;
    const cur = scan.scan_config?.current_step ?? 0;
    const total = scan.scan_config?.total_steps ?? 0;
    if (!total) return 5; // running, first step not reported yet
    return Math.min(99, Math.max(5, Math.round((cur / total) * 100)));
  };

  const isScanning = currentScan?.status === 'running';
  const scanProgress = getScanProgress(currentScan);

  const handleStartScan = async () => {
    // SECURITY FIX: Client-side form validation
    const validation = validateScanForm(targetUrl, selectedTools);
    setFormErrors(validation.errors);

    if (!validation.isValid) {
      toast({
        title: "Validation Failed",
        description: "Please correct the errors in the form",
        variant: "destructive",
      });
      return;
    }

    // Additional SSRF check (defense in depth)
    if (!isValidPublicUrl(targetUrl)) {
      setFormErrors({
        targetUrl: "Cannot scan internal IPs or localhost. Please use a public URL.",
      });
      toast({
        title: "Invalid Target URL",
        description: "Cannot scan internal IPs or localhost. Please use a public URL.",
        variant: "destructive",
      });
      return;
    }

    await startScan(targetUrl, selectedTools, scanProfile);
  };

  const handleStopScan = async () => {
    if (currentScan?.id) {
      await stopScan(currentScan.id);
    }
  };

  const formatLogs = () => {
    return scanLogs.map(log =>
      `[${new Date(log.timestamp).toLocaleTimeString()}] ${log.message}`
    ).join('\n');
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <Scan className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Security Scanner</h1>
          <p className="text-muted-foreground">Configure and run OWASP Top 10 vulnerability scans</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Configuration Panel */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
              <CardDescription>Configure your security scan parameters</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target">Target URL</Label>
                <Input
                  id="target"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => {
                    setTargetUrl(e.target.value);
                    // Clear error when user starts typing
                    if (formErrors.targetUrl) {
                      setFormErrors({ ...formErrors, targetUrl: '' });
                    }
                  }}
                  disabled={isScanning}
                  className={cn(formErrors.targetUrl && "border-red-500")}
                />
                {formErrors.targetUrl && (
                  <div className="flex items-center gap-2 text-sm text-red-600">
                    <AlertCircle className="h-4 w-4" />
                    {formErrors.targetUrl}
                  </div>
                )}
              </div>

              {/* Scan depth: Quick vs Deep */}
              <div className="space-y-2">
                <Label>Scan Depth</Label>
                <div className="grid grid-cols-2 gap-2">
                  <button
                    type="button"
                    disabled={isScanning}
                    onClick={() => setScanProfile('quick')}
                    className={cn(
                      "rounded-lg border p-3 text-left transition-all disabled:opacity-50",
                      scanProfile === 'quick'
                        ? "border-primary bg-primary/10 ring-1 ring-primary"
                        : "border-border hover:bg-accent/50"
                    )}
                  >
                    <div className="font-semibold text-sm">⚡ Quick</div>
                    <div className="text-xs text-muted-foreground">Fewer ports, high/medium checks. Faster.</div>
                  </button>
                  <button
                    type="button"
                    disabled={isScanning}
                    onClick={() => setScanProfile('deep')}
                    className={cn(
                      "rounded-lg border p-3 text-left transition-all disabled:opacity-50",
                      scanProfile === 'deep'
                        ? "border-primary bg-primary/10 ring-1 ring-primary"
                        : "border-border hover:bg-accent/50"
                    )}
                  >
                    <div className="font-semibold text-sm">🔬 Deep</div>
                    <div className="text-xs text-muted-foreground">More ports, all templates. Slower, thorough.</div>
                  </button>
                </div>
              </div>

              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <Label>Security Tools</Label>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="xs"
                      onClick={() => setSelectedTools(["subfinder", "securityheaders", "retire"])}
                      disabled={isScanning}
                      className="text-xs h-7 px-2"
                    >
                      Quick
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      onClick={() => setSelectedTools(["nikto", "nuclei", "sqlmap", "dalfox", "gobuster", "ffuf", "whatweb", "securityheaders", "retire", "wpscan"])}
                      disabled={isScanning}
                      className="text-xs h-7 px-2"
                    >
                      Full Web
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      onClick={() => setSelectedTools(["nmap", "testssl", "subfinder"])}
                      disabled={isScanning}
                      className="text-xs h-7 px-2"
                    >
                      Network
                    </Button>
                    <Button
                      variant="outline"
                      size="xs"
                      onClick={() => setSelectedTools([])}
                      disabled={isScanning}
                      className="text-xs h-7 px-2"
                    >
                      Clear
                    </Button>
                  </div>
                </div>

                {formErrors.tools && (
                  <div className="flex items-center gap-2 text-sm text-red-600">
                    <AlertCircle className="h-4 w-4" />
                    {formErrors.tools}
                  </div>
                )}

                <Accordion type="multiple" defaultValue={["Web", "Recon"]} className="border border-border/50 rounded-lg p-2 bg-card/50">
                  {["Recon", "Web", "Vulnerability", "Injection", "SSL", "CMS"].map((category) => {
                    const categoryTools = tools.filter(t => t.category === category);
                    if (categoryTools.length === 0) return null;
                    const allChecked = categoryTools.every(t => selectedTools.includes(t.id));

                    return (
                      <AccordionItem key={category} value={category} className="border-b-0">
                        <div className="flex items-center justify-between px-2">
                          <AccordionTrigger className="hover:no-underline py-2 text-sm font-semibold flex-1">
                            {category} ({categoryTools.filter(t => selectedTools.includes(t.id)).length}/{categoryTools.length})
                          </AccordionTrigger>
                          <Checkbox
                            checked={allChecked}
                            disabled={isScanning}
                            onCheckedChange={(checked) => {
                              const toolIds = categoryTools.map(t => t.id);
                              if (checked) {
                                setSelectedTools(Array.from(new Set([...selectedTools, ...toolIds])));
                              } else {
                                setSelectedTools(selectedTools.filter(id => !toolIds.includes(id)));
                              }
                            }}
                            className="mr-2"
                          />
                        </div>
                        <AccordionContent className="px-4 pb-2 pt-1 space-y-3 border-t border-border/20 mt-1">
                          {categoryTools.map((tool) => (
                            <div key={tool.id} className="flex items-center space-x-3">
                              <Checkbox
                                id={tool.id}
                                checked={selectedTools.includes(tool.id)}
                                onCheckedChange={(checked) => {
                                  if (checked) {
                                    setSelectedTools([...selectedTools, tool.id]);
                                  } else {
                                    setSelectedTools(selectedTools.filter(id => id !== tool.id));
                                  }
                                  if (formErrors.tools) {
                                    setFormErrors({ ...formErrors, tools: '' });
                                  }
                                }}
                                disabled={isScanning}
                              />
                              <div className="flex items-center gap-2 flex-1">
                                <tool.icon className="h-4 w-4 text-primary" />
                                <div>
                                  <label htmlFor={tool.id} className="text-sm font-medium cursor-pointer">
                                    {tool.name}
                                  </label>
                                  <p className="text-xs text-muted-foreground">{tool.description}</p>
                                </div>
                              </div>
                            </div>
                          ))}
                        </AccordionContent>
                      </AccordionItem>
                    );
                  })}
                </Accordion>
              </div>

              <div className="flex gap-2 pt-4">
                {!isScanning ? (
                  <Button onClick={handleStartScan} className="flex-1" disabled={!targetUrl || loading}>
                    <Play className="mr-2 h-4 w-4" />
                    {loading ? "Starting..." : "Start Scan"}
                  </Button>
                ) : (
                  <Button onClick={handleStopScan} variant="destructive" className="flex-1">
                    <Square className="mr-2 h-4 w-4" />
                    Stop Scan
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Scan Progress */}
          {(currentScan || scanProgress > 0) && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  {isScanning ? (
                    <Clock className="h-5 w-5 text-primary animate-spin" />
                  ) : (
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  )}
                  Scan Progress
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Overall Progress</span>
                    <span>{scanProgress}%</span>
                  </div>
                  <Progress value={scanProgress} className="w-full" />
                </div>

                {currentScan && (
                  <div className="space-y-2">
                    <Label>Current Status</Label>
                    <Badge variant="outline" className="w-full justify-start">
                      {currentScan.status.charAt(0).toUpperCase() + currentScan.status.slice(1)}
                    </Badge>
                  </div>
                )}

                {currentScan?.scan_config?.total_steps ? (
                  <div className="space-y-2">
                    <Label>Step</Label>
                    <p className="text-sm text-muted-foreground">
                      {currentScan.scan_config.current_step ?? 0} / {currentScan.scan_config.total_steps} stages
                      {isScanning ? " running…" : " done"}
                    </p>
                  </div>
                ) : null}

                {findings.length > 0 && (
                  <div className="space-y-2">
                    <Label>Findings Detected ({findings.length})</Label>
                    <div className="flex flex-wrap gap-2">
                      <Badge variant="critical" className="text-xs">
                        {findings.filter(f => f.severity === 'Critical').length} Critical
                      </Badge>
                      <Badge variant="high" className="text-xs">
                        {findings.filter(f => f.severity === 'High').length} High
                      </Badge>
                      <Badge variant="medium" className="text-xs">
                        {findings.filter(f => f.severity === 'Medium').length} Medium
                      </Badge>
                      <Badge variant="low" className="text-xs">
                        {findings.filter(f => f.severity === 'Low').length} Low
                      </Badge>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </div>

        {/* Live Logs */}
        <Card className="lg:col-span-1">
          <CardHeader>
            <CardTitle>Live Scan Logs</CardTitle>
            <CardDescription>Real-time output from security tools</CardDescription>
          </CardHeader>
          <CardContent>
            <Textarea
              value={formatLogs()}
              readOnly
              className="min-h-[400px] font-mono text-sm bg-muted/20"
              placeholder="Scan logs will appear here..."
            />
          </CardContent>
        </Card>
      </div>
    </div>
  );
}