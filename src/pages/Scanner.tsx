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
import { getCSRFToken, cn } from "@/lib/utils";
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

const tools = [
  { id: "zap", name: "OWASP ZAP", description: "Web Application Security Scanner", icon: Zap, enabled: true, category: "Web" },
  { id: "sqlmap", name: "SQLMap", description: "SQL Injection Testing", icon: Database, enabled: true, category: "Web" },
  { id: "nikto", name: "Nikto", description: "Web Server Scanner", icon: Globe, enabled: true, category: "Web" },
  { id: "retire", name: "Retire.js", description: "JavaScript Vulnerabilities", icon: Search, enabled: false, category: "Web" },
  { id: "subfinder", name: "Subfinder", description: "Subdomain Discovery Tool", icon: Link, enabled: false, category: "Recon" },
  { id: "gobuster", name: "Gobuster", description: "Directory & File Fuzzing Tool", icon: FolderSearch, enabled: false, category: "Recon" },
  { id: "wapiti", name: "Wapiti", description: "Web App Vulnerability Scanner", icon: FileCode, enabled: false, category: "Web" },
  { id: "nuclei", name: "Nuclei", description: "Template-based CVE Scanner", icon: Cpu, enabled: false, category: "Vulnerability" },
  { id: "hydra", name: "Hydra", description: "Login Brute-Force Testing Tool", icon: KeyRound, enabled: false, category: "Authentication" },
  { id: "ffuf", name: "ffuf", description: "Web Parameter & Header Fuzzer", icon: Terminal, enabled: false, category: "Recon" },
  { id: "xsstrike", name: "XSStrike", description: "Advanced XSS Detection Suite", icon: Bug, enabled: false, category: "XSS" },
  { id: "dalfox", name: "Dalfox", description: "Fast XSS Parameter Scanner", icon: Sparkles, enabled: false, category: "XSS" },
  { id: "testssl", name: "testssl.sh", description: "SSL/TLS Configuration Auditor", icon: ShieldAlert, enabled: false, category: "SSL" },
  { id: "securityheaders", name: "SecurityHeaders.com", description: "HTTP Security Header Checker", icon: Shield, enabled: false, category: "SSL" },
  { id: "wpscan", name: "WPScan", description: "WordPress Security Scanner", icon: Fingerprint, enabled: false, category: "CMS" },
  { id: "nmap", name: "Nmap", description: "Port Scanner & Service Detector", icon: Server, enabled: false, category: "Recon" },
  { id: "metasploit", name: "Metasploit", description: "Exploit Verification Framework", icon: Skull, enabled: false, category: "Exploits" },
];

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

export default function Scanner() {
  const [targetUrl, setTargetUrl] = useState("");
  const [selectedTools, setSelectedTools] = useState(tools.filter(t => t.enabled).map(t => t.id));
  const [formErrors, setFormErrors] = useState<Record<string, string>>({});
  const { toast } = useToast();
  const { 
    currentScan, 
    scanLogs, 
    findings, 
    loading, 
    startScan, 
    stopScan 
  } = useScanOrchestrator();

  // Load enabled tools from settings on mount
  useEffect(() => {
    const savedTools = localStorage.getItem("owasp_shield_settings_tools");
    if (savedTools) {
      try {
        const parsed = JSON.parse(savedTools);
        const enabledIds = parsed
          .filter((t: any) => t.settings?.enabled)
          .map((t: any) => t.id);
        setSelectedTools(enabledIds);
      } catch (e) {
        console.error("Error loading enabled tools from settings:", e);
      }
    }
  }, []);

  const getScanProgress = (status: string, logs: any[]) => {
    if (status === 'completed' || status === 'failed' || status === 'cancelled') {
      return 100;
    }
    if (status === 'pending') {
      return 0;
    }
    
    // Find the latest step from scanSteps that is present in the logs
    let latestStepIndex = -1;
    logs.forEach(log => {
      const stepIdx = scanSteps.findIndex(step => log.message.includes(step));
      if (stepIdx > latestStepIndex) {
        latestStepIndex = stepIdx;
      }
    });

    if (latestStepIndex === -1) {
      return 5;
    }

    const baseProgress = Math.round(((latestStepIndex + 1) / scanSteps.length) * 95);
    return Math.min(95, Math.max(10, baseProgress));
  };

  const getStepStatus = (stepName: string, index: number) => {
    if (!currentScan) return 'pending';
    if (currentScan.status === 'completed') return 'completed';
    if (currentScan.status === 'failed' || currentScan.status === 'cancelled') {
      const stepLogged = scanLogs.some(log => log.message.includes(stepName));
      return stepLogged ? 'completed' : 'cancelled';
    }

    const stepLogged = scanLogs.some(log => log.message.includes(stepName));
    if (!stepLogged) return 'pending';

    const nextStep = scanSteps[index + 1];
    if (!nextStep) {
      return 'running';
    }
    const nextStepLogged = scanLogs.some(log => log.message.includes(nextStep));
    return nextStepLogged ? 'completed' : 'running';
  };

  const isScanning = currentScan?.status === 'running';
  const scanProgress = currentScan ? getScanProgress(currentScan.status, scanLogs) : 0;

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

    await startScan(targetUrl, selectedTools);
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
                      onClick={() => setSelectedTools(["zap", "sqlmap", "nikto", "wapiti", "nuclei", "xsstrike", "dalfox", "securityheaders", "retire"])}
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
                  {["Recon", "Web", "Vulnerability", "XSS", "SSL", "CMS", "Authentication", "Exploits"].map((category) => {
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

                {findings.length > 0 && (
                  <div className="space-y-2">
                    <Label>Findings Detected</Label>
                    <div className="flex gap-2">
                      <Badge variant="critical" className="text-xs">
                        {findings.filter(f => f.severity === 'High').length} High
                      </Badge>
                      <Badge variant="high" className="text-xs">
                        {findings.filter(f => f.severity === 'Medium').length} Medium
                      </Badge>
                      <Badge variant="medium" className="text-xs">
                        {findings.filter(f => f.severity === 'Low').length} Low
                      </Badge>
                    </div>
                  </div>
                )}

                {currentScan && (
                  <div className="pt-4 border-t space-y-3">
                    <Label className="text-sm font-semibold">Scan Steps</Label>
                    <div className="space-y-2.5 max-h-[300px] overflow-y-auto pr-1">
                      {scanSteps.map((stepName, index) => {
                        const status = getStepStatus(stepName, index);
                        return (
                          <div key={index} className="flex items-center justify-between text-xs transition-all duration-200">
                            <div className="flex items-center gap-2">
                              {status === 'completed' && (
                                <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                              )}
                              {status === 'running' && (
                                <Clock className="h-4 w-4 text-primary animate-spin shrink-0" />
                              )}
                              {status === 'pending' && (
                                <div className="h-4 w-4 rounded-full border border-muted-foreground/30 bg-muted/10 shrink-0" />
                              )}
                              {status === 'cancelled' && (
                                <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />
                              )}
                              <span className={cn(
                                status === 'running' && "font-semibold text-foreground",
                                status === 'completed' && "text-muted-foreground line-through decoration-muted-foreground/40",
                                status === 'pending' && "text-muted-foreground/60",
                                status === 'cancelled' && "text-yellow-600/70"
                              )}>
                                {stepName}
                              </span>
                            </div>
                            {status === 'running' && (
                              <Badge variant="outline" className="text-[9px] py-0 px-1.5 animate-pulse bg-primary/5 text-primary border-primary/20">
                                Scanning
                              </Badge>
                            )}
                            {status === 'completed' && (
                              <span className="text-[10px] text-green-600 font-medium">Done</span>
                            )}
                            {status === 'cancelled' && (
                              <span className="text-[10px] text-yellow-600 font-medium">Skipped</span>
                            )}
                          </div>
                        );
                      })}
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