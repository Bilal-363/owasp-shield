import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { cn } from "@/lib/utils";
import {
  Settings as SettingsIcon,
  Info,
  Server,
  Link,
  FolderSearch,
  Terminal,
  Fingerprint,
  Cpu,
  Globe,
  Search,
  Database,
  Sparkles,
  ShieldAlert,
  Shield,
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";

// The single source of truth for tools — must match the Scanner page.
const TOOLS = [
  { id: "nmap", name: "Nmap", description: "Port Scanner & Service Detector", icon: Server, category: "Recon" },
  { id: "subfinder", name: "Subfinder", description: "Subdomain Discovery", icon: Link, category: "Recon" },
  { id: "gobuster", name: "Gobuster", description: "Directory & File Discovery", icon: FolderSearch, category: "Recon" },
  { id: "ffuf", name: "ffuf", description: "Endpoint Fuzzer", icon: Terminal, category: "Recon" },
  { id: "whatweb", name: "WhatWeb", description: "Technology Fingerprinting", icon: Fingerprint, category: "Recon" },
  { id: "nuclei", name: "Nuclei", description: "Template-based CVE Scanner", icon: Cpu, category: "Vulnerability" },
  { id: "nikto", name: "Nikto", description: "Web Server Scanner", icon: Globe, category: "Web" },
  { id: "retire", name: "Retire.js", description: "Outdated JS Libraries", icon: Search, category: "Web" },
  { id: "sqlmap", name: "SQLMap", description: "SQL Injection Testing", icon: Database, category: "Injection" },
  { id: "dalfox", name: "Dalfox", description: "XSS Testing", icon: Sparkles, category: "Injection" },
  { id: "testssl", name: "sslscan", description: "SSL/TLS Configuration Audit", icon: ShieldAlert, category: "SSL" },
  { id: "securityheaders", name: "Security Headers", description: "HTTP Security Header Check", icon: Shield, category: "SSL" },
  { id: "wpscan", name: "WPScan", description: "WordPress Security Scanner", icon: Cpu, category: "CMS" },
];

const CATEGORIES = ["Recon", "Web", "Vulnerability", "Injection", "SSL", "CMS"];

// Same localStorage keys the Scanner reads — this is what makes them sync.
const SELECTED_KEY = "owasp_shield_scanner_selected_tools";
const PROFILE_KEY = "owasp_shield_scan_profile";

export default function Settings() {
  const { toast } = useToast();

  const [enabled, setEnabled] = useState<string[]>(() => {
    const saved = localStorage.getItem(SELECTED_KEY);
    if (saved) {
      try {
        return JSON.parse(saved);
      } catch {
        /* ignore */
      }
    }
    return TOOLS.map((t) => t.id); // default: all enabled
  });

  const [profile, setProfile] = useState<"quick" | "deep">(
    () => (localStorage.getItem(PROFILE_KEY) as "quick" | "deep") || "quick"
  );

  // Persist — the Scanner reads these same keys, so changes sync across pages.
  useEffect(() => {
    localStorage.setItem(SELECTED_KEY, JSON.stringify(enabled));
  }, [enabled]);

  useEffect(() => {
    localStorage.setItem(PROFILE_KEY, profile);
  }, [profile]);

  const toggle = (id: string) =>
    setEnabled((prev) => (prev.includes(id) ? prev.filter((x) => x !== id) : [...prev, id]));

  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <SettingsIcon className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Defaults applied when you open the Scanner.</p>
        </div>
      </div>

      <Alert>
        <Info className="h-4 w-4" />
        <AlertTitle>These are defaults — they sync with the Scanner page</AlertTitle>
        <AlertDescription>
          Whatever you enable here is pre-selected on the Scanner. You can still change tools per-scan
          on the Scanner page. Tools only run if they&apos;re installed on the backend (all of them run
          in the Docker setup; without Docker the built-in checks still run).
        </AlertDescription>
      </Alert>

      {/* Default scan depth */}
      <Card>
        <CardHeader>
          <CardTitle className="text-lg">Default Scan Depth</CardTitle>
          <CardDescription>How thorough each scan is by default.</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => setProfile("quick")}
              className={cn(
                "rounded-lg border p-4 text-left transition-all",
                profile === "quick" ? "border-primary bg-primary/10 ring-1 ring-primary" : "border-border hover:bg-accent/50"
              )}
            >
              <div className="font-semibold">⚡ Quick</div>
              <div className="text-xs text-muted-foreground">Fewer ports, high/medium checks. Faster.</div>
            </button>
            <button
              type="button"
              onClick={() => setProfile("deep")}
              className={cn(
                "rounded-lg border p-4 text-left transition-all",
                profile === "deep" ? "border-primary bg-primary/10 ring-1 ring-primary" : "border-border hover:bg-accent/50"
              )}
            >
              <div className="font-semibold">🔬 Deep</div>
              <div className="text-xs text-muted-foreground">More ports, all templates. Slower, thorough.</div>
            </button>
          </div>
        </CardContent>
      </Card>

      {/* Default tools */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-lg">Default Tools ({enabled.length}/{TOOLS.length})</CardTitle>
              <CardDescription>Which tools are pre-selected on the Scanner.</CardDescription>
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" onClick={() => setEnabled(TOOLS.map((t) => t.id))}>
                Enable all
              </Button>
              <Button variant="outline" size="sm" onClick={() => setEnabled([])}>
                Disable all
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-6">
          {CATEGORIES.map((cat) => {
            const items = TOOLS.filter((t) => t.category === cat);
            if (!items.length) return null;
            return (
              <div key={cat} className="space-y-2">
                <Label className="text-xs uppercase tracking-wider text-muted-foreground">{cat}</Label>
                <div className="grid gap-2 sm:grid-cols-2">
                  {items.map((tool) => (
                    <div
                      key={tool.id}
                      className="flex items-center justify-between rounded-lg border border-border/60 p-3"
                    >
                      <div className="flex items-center gap-3">
                        <tool.icon className="h-5 w-5 text-primary shrink-0" />
                        <div>
                          <div className="text-sm font-medium">{tool.name}</div>
                          <div className="text-xs text-muted-foreground">{tool.description}</div>
                        </div>
                      </div>
                      <Switch checked={enabled.includes(tool.id)} onCheckedChange={() => toggle(tool.id)} />
                    </div>
                  ))}
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button
          onClick={() =>
            toast({ title: "Saved", description: "Defaults updated. They apply on the Scanner page." })
          }
        >
          Save
        </Button>
      </div>
    </div>
  );
}
