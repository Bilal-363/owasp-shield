import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { 
  Shield, 
  Scan, 
  AlertTriangle, 
  Search, 
  Database, 
  Globe,
  ArrowRight,
  Zap,
  Lock,
  Server,
  Link,
  FolderSearch,
  Cpu,
  KeyRound,
  Terminal,
  Bug,
  Sparkles,
  Fingerprint,
  ShieldAlert,
  FileCode,
  Skull
} from "lucide-react";

const owaspTop10 = [
  { 
    id: "A01", 
    title: "Broken Access Control", 
    description: "Restrictions on what authenticated users are allowed to do are often not properly enforced.",
    severity: "Critical"
  },
  { 
    id: "A02", 
    title: "Cryptographic Failures", 
    description: "Failures related to cryptography which often leads to sensitive data exposure.",
    severity: "High"
  },
  { 
    id: "A03", 
    title: "Injection", 
    description: "Injection flaws, such as SQL, NoSQL, OS, and LDAP injection occur when untrusted data is sent to an interpreter.",
    severity: "Critical"
  },
  { 
    id: "A04", 
    title: "Insecure Design", 
    description: "Risks related to design flaws, calling for more use of threat modeling and secure design patterns.",
    severity: "High"
  },
  { 
    id: "A05", 
    title: "Security Misconfiguration", 
    description: "Security misconfiguration is commonly a result of insecure default configurations.",
    severity: "Medium"
  },
  { 
    id: "A06", 
    title: "Vulnerable Components", 
    description: "Applications and APIs using components with known vulnerabilities may undermine application defenses.",
    severity: "High"
  },
];

const tools = [
  { name: "OWASP ZAP", description: "Web Application Security Scanner", icon: Zap, category: "Web" },
  { name: "SQLMap", description: "SQL Injection Testing Tool", icon: Database, category: "Web" },
  { name: "Nikto", description: "Web Server Scanner", icon: Globe, category: "Web" },
  { name: "Retire.js", description: "JavaScript Vulnerability Scanner", icon: Search, category: "Web" },
  { name: "Subfinder", description: "Subdomain Discovery Tool", icon: Link, category: "Recon" },
  { name: "Gobuster", description: "Directory & File Fuzzing Tool", icon: FolderSearch, category: "Recon" },
  { name: "Wapiti", description: "Web App Vulnerability Scanner", icon: FileCode, category: "Web" },
  { name: "Nuclei", description: "Template-based CVE Scanner", icon: Cpu, category: "Vulnerability" },
  { name: "Hydra", description: "Login Brute-Force Testing Tool", icon: KeyRound, category: "Authentication" },
  { name: "ffuf", description: "Web Parameter & Header Fuzzer", icon: Terminal, category: "Recon" },
  { name: "XSStrike", description: "Advanced XSS Detection Suite", icon: Bug, category: "XSS" },
  { name: "Dalfox", description: "Fast XSS Parameter Scanner", icon: Sparkles, category: "XSS" },
  { name: "testssl.sh", description: "SSL/TLS Configuration Auditor", icon: ShieldAlert, category: "SSL" },
  { name: "SecurityHeaders.com", description: "HTTP Security Header Checker", icon: Shield, category: "SSL" },
  { name: "WPScan", description: "WordPress Security Scanner", icon: Fingerprint, category: "CMS" },
  { name: "Nmap", description: "Port Scanner & Service Detector", icon: Server, category: "Recon" },
  { name: "Metasploit", description: "Exploit Verification Framework", icon: Skull, category: "Exploits" },
];

export default function Index() {
  const navigate = useNavigate();
  const { user } = useAuth();
  const [activeCategory, setActiveCategory] = useState("All");

  const categories = ["All", "Recon", "Web", "Vulnerability", "XSS", "SSL", "CMS", "Authentication", "Exploits"];

  const filteredTools = activeCategory === "All"
    ? tools
    : tools.filter(t => t.category === activeCategory);

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "critical";
      case "High": return "high";
      case "Medium": return "medium";
      default: return "low";
    }
  };

  return (
    <div className="min-h-screen bg-gradient-scanner">
      {/* Hero Section */}
      <section className="relative py-20 px-6 overflow-hidden">
        <div className="absolute inset-0 bg-gradient-hero opacity-10"></div>
        <div className="relative max-w-6xl mx-auto text-center">
          <div className="flex justify-center mb-6">
            <Shield className="h-20 w-20 text-primary shadow-glow" />
          </div>
          <h1 className="text-5xl font-bold mb-6 bg-gradient-to-r from-primary to-accent bg-clip-text text-transparent">
            Welcome back, {user?.email?.split('@')[0]}
          </h1>
          <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto">
            Professional-grade automated security scanner for detecting OWASP Top 10 vulnerabilities. 
            Integrated penetration testing tools with comprehensive reporting.
          </p>
          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="bg-primary hover:bg-primary/90 shadow-glow"
              onClick={() => navigate("/scanner")}
            >
              <Scan className="mr-2 h-5 w-5" />
              Start Security Scan
              <ArrowRight className="ml-2 h-5 w-5" />
            </Button>
            <Button variant="outline" size="lg" onClick={() => navigate("/results")}>
              <AlertTriangle className="mr-2 h-5 w-5" />
              View Previous Results
            </Button>
          </div>
        </div>
      </section>

      {/* OWASP Top 10 Section */}
      <section className="py-16 px-6">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">OWASP Top 10 Coverage</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto">
              Our scanner is designed to detect the most critical web application security risks as defined by OWASP.
            </p>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {owaspTop10.map((item) => (
              <Card key={item.id} className="hover:shadow-scanner transition-all duration-300 border-border/50">
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <Badge variant="outline" className="font-mono">
                      {item.id}:2021
                    </Badge>
                    <Badge variant={getSeverityColor(item.severity) as any}>
                      {item.severity}
                    </Badge>
                  </div>
                  <CardTitle className="text-lg">{item.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-sm">
                    {item.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Integrated Tools Section */}
      <section className="py-16 px-6 bg-card/20">
        <div className="max-w-6xl mx-auto">
          <div className="text-center mb-12">
            <h2 className="text-3xl font-bold mb-4">Integrated Security Tools</h2>
            <p className="text-muted-foreground mb-8">
              Industry-leading penetration testing tools unified in one interface.
            </p>
            
            <div className="flex flex-wrap gap-2 justify-center mb-8">
              {categories.map((cat) => (
                <Button
                  key={cat}
                  variant={activeCategory === cat ? "default" : "outline"}
                  size="sm"
                  onClick={() => setActiveCategory(cat)}
                  className={activeCategory === cat ? "bg-primary text-primary-foreground shadow-glow" : ""}
                >
                  {cat}
                </Button>
              ))}
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {filteredTools.map((tool) => (
              <Card key={tool.name} className="text-center hover:shadow-cyber transition-all duration-300">
                <CardHeader>
                  <tool.icon className="h-12 w-12 text-primary mx-auto mb-4" />
                  <CardTitle className="text-lg">{tool.name}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription>{tool.description}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-16 px-6">
        <div className="max-w-4xl mx-auto text-center">
          <h2 className="text-3xl font-bold mb-8">Professional Security Testing</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
            <div className="flex flex-col items-center">
              <Lock className="h-12 w-12 text-primary mb-4" />
              <h3 className="text-lg font-semibold mb-2">Comprehensive Scanning</h3>
              <p className="text-muted-foreground text-sm">
                Multi-tool orchestration for complete vulnerability assessment
              </p>
            </div>
            <div className="flex flex-col items-center">
              <AlertTriangle className="h-12 w-12 text-high mb-4" />
              <h3 className="text-lg font-semibold mb-2">Real-time Results</h3>
              <p className="text-muted-foreground text-sm">
                Live progress tracking with instant vulnerability detection
              </p>
            </div>
            <div className="flex flex-col items-center">
              <Shield className="h-12 w-12 text-info mb-4" />
              <h3 className="text-lg font-semibold mb-2">Professional Reports</h3>
              <p className="text-muted-foreground text-sm">
                Executive summaries and technical details in multiple formats
              </p>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}