import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import {
  BookOpen,
  ShieldAlert,
  Play,
  ListChecks,
  FileText,
  Server,
  Wrench,
  AlertTriangle,
  ExternalLink,
} from "lucide-react";

const tools = [
  { name: "nmap", desc: "Open ports & service/version detection" },
  { name: "nuclei", desc: "Template-based CVE / misconfiguration scanning" },
  { name: "nikto", desc: "Web-server vulnerability scan" },
  { name: "gobuster / ffuf", desc: "Hidden directory & endpoint discovery" },
  { name: "sslscan", desc: "TLS/SSL cipher & protocol audit" },
  { name: "whatweb", desc: "Technology fingerprinting" },
  { name: "subfinder", desc: "Subdomain enumeration" },
  { name: "wpscan", desc: "WordPress core/plugin vulnerabilities" },
  { name: "sqlmap", desc: "Active SQL-injection testing (lab only)" },
  { name: "dalfox", desc: "Active XSS testing (lab only)" },
];

const severities = [
  { label: "Critical", cls: "bg-red-600 text-white", desc: "Exploitable now, severe impact — fix immediately." },
  { label: "High", cls: "bg-orange-500 text-white", desc: "Serious weakness — fix as a priority." },
  { label: "Medium", cls: "bg-amber-500 text-white", desc: "Should be fixed; moderate risk." },
  { label: "Low", cls: "bg-blue-500 text-white", desc: "Hardening / best-practice improvement." },
  { label: "Info", cls: "bg-slate-500 text-white", desc: "Informational — no direct risk." },
];

const steps = [
  {
    icon: Server,
    title: "1. Make sure the scanner backend is running",
    body:
      "The real scanning engine runs as a separate service (Docker). If scans fail instantly with a connection error, the backend isn't running or the app can't reach it. See the project README to start it (docker compose up).",
  },
  {
    icon: Play,
    title: "2. Start a scan",
    body:
      "Go to Scanner, paste the full URL of a site you own or are authorized to test (e.g. https://yourapp.com), pick the tools (or leave all selected to run everything), choose Quick or Deep, and press Start.",
  },
  {
    icon: ListChecks,
    title: "3. Watch it live",
    body:
      "Findings and tool output stream in real time on the Results page. A Quick scan takes a few minutes; a Deep scan (full nuclei templates, sqlmap, etc.) can take much longer — that's the tools being thorough, not a freeze.",
  },
  {
    icon: FileText,
    title: "4. Read findings & export a report",
    body:
      "Each finding shows severity, the OWASP category, affected URL, evidence, and a recommendation. From Reports you can export HTML / PDF / CSV to share or attach to your submission.",
  },
];

export default function Guide() {
  return (
    <div className="p-6 max-w-4xl mx-auto space-y-6">
      <div className="flex items-center gap-3">
        <BookOpen className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-2xl font-bold">How to Use OWASP Shield</h1>
          <p className="text-muted-foreground">A quick guide to running a real security scan.</p>
        </div>
      </div>

      {/* Legal warning first — most important */}
      <Alert variant="destructive">
        <ShieldAlert className="h-4 w-4" />
        <AlertTitle>Only scan systems you own or are allowed to test</AlertTitle>
        <AlertDescription>
          This tool runs real security tools that actively probe (and, with sqlmap/dalfox, attack)
          the target. Scanning a website without the owner&apos;s permission is illegal in most
          countries. For practice, use a deliberately-vulnerable app like{" "}
          <span className="font-semibold">OWASP Juice Shop</span> or <span className="font-semibold">DVWA</span>.
        </AlertDescription>
      </Alert>

      {/* Steps */}
      <div className="grid gap-4 sm:grid-cols-2">
        {steps.map((s) => (
          <Card key={s.title}>
            <CardHeader className="pb-2">
              <CardTitle className="flex items-center gap-2 text-base">
                <s.icon className="h-5 w-5 text-primary" />
                {s.title}
              </CardTitle>
            </CardHeader>
            <CardContent className="text-sm text-muted-foreground">{s.body}</CardContent>
          </Card>
        ))}
      </div>

      {/* Quick vs Deep */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="flex items-center gap-2 text-base">
            <Wrench className="h-5 w-5 text-primary" />
            Quick vs Deep scan
          </CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-2">
          <p>
            <span className="font-semibold text-foreground">Quick</span> — fewer ports, high/medium
            severity templates, faster. Good for a first look.
          </p>
          <p>
            <span className="font-semibold text-foreground">Deep</span> — more ports, all templates,
            higher sqlmap level/risk. Much more thorough, but can take a long time.
          </p>
        </CardContent>
      </Card>

      {/* Severities */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">Understanding severity levels</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {severities.map((s) => (
            <div key={s.label} className="flex items-center gap-3 text-sm">
              <Badge className={`${s.cls} w-20 justify-center`}>{s.label}</Badge>
              <span className="text-muted-foreground">{s.desc}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Tools */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-base">What the tools do</CardTitle>
        </CardHeader>
        <CardContent className="grid gap-2 sm:grid-cols-2">
          {tools.map((t) => (
            <div key={t.name} className="text-sm">
              <span className="font-mono font-semibold text-foreground">{t.name}</span>
              <span className="text-muted-foreground"> — {t.desc}</span>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* No results note */}
      <Alert>
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>No findings? That can be good.</AlertTitle>
        <AlertDescription>
          A clean, well-configured site may legitimately return only Info/Low findings. Unlike the
          old version, this scanner never invents results — it reports only what it actually observes.
        </AlertDescription>
      </Alert>

      <p className="text-xs text-muted-foreground flex items-center gap-1">
        <ExternalLink className="h-3 w-3" />
        Full setup &amp; hosting instructions are in the project&apos;s <code>scanner-backend/README.md</code>.
      </p>
    </div>
  );
}
