import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Slider } from "@/components/ui/slider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { 
  Settings as SettingsIcon, 
  Wrench, 
  Shield, 
  Bell,
  Database,
  Globe,
  Zap,
  Search,
  CheckCircle,
  AlertTriangle,
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
import { useToast } from "@/hooks/use-toast";

interface ToolSettings {
  enabled: boolean;
  timeout: number;
  depth?: number;
  threads?: number;
  risk?: number;
  level?: number;
  useragent?: string;
  wordlist?: string;
  severity?: string;
  service?: string;
  ports?: string;
  enumerate?: string;
}

interface ToolConfig {
  id: string;
  name: string;
  icon: any;
  status: string;
  version: string;
  settings: ToolSettings;
}

const toolConfigs: ToolConfig[] = [
  {
    id: "zap",
    name: "OWASP ZAP",
    icon: Zap,
    status: "active",
    version: "2.12.0",
    settings: {
      enabled: true,
      timeout: 300,
      depth: 3,
      threads: 10
    }
  },
  {
    id: "sqlmap", 
    name: "SQLMap",
    icon: Database,
    status: "active",
    version: "1.7.2",
    settings: {
      enabled: true,
      timeout: 600,
      risk: 2,
      level: 3
    }
  },
  {
    id: "nikto",
    name: "Nikto",
    icon: Globe, 
    status: "active",
    version: "2.5.0",
    settings: {
      enabled: true,
      timeout: 300,
      useragent: "Mozilla/5.0"
    }
  },
  {
    id: "retire",
    name: "Retire.js",
    icon: Search,
    status: "inactive",
    version: "4.2.3",
    settings: {
      enabled: false,
      timeout: 120
    }
  },
  {
    id: "subfinder",
    name: "Subfinder",
    icon: Link,
    status: "inactive",
    version: "2.6.3",
    settings: {
      enabled: false,
      timeout: 180,
      threads: 10
    }
  },
  {
    id: "gobuster",
    name: "Gobuster",
    icon: FolderSearch,
    status: "inactive",
    version: "3.6.0",
    settings: {
      enabled: false,
      timeout: 300,
      threads: 10,
      wordlist: "common.txt"
    }
  },
  {
    id: "wapiti",
    name: "Wapiti",
    icon: FileCode,
    status: "inactive",
    version: "3.1.6",
    settings: {
      enabled: false,
      timeout: 240,
      depth: 2
    }
  },
  {
    id: "nuclei",
    name: "Nuclei",
    icon: Cpu,
    status: "inactive",
    version: "3.1.8",
    settings: {
      enabled: false,
      timeout: 300,
      severity: "medium,high,critical"
    }
  },
  {
    id: "hydra",
    name: "Hydra",
    icon: KeyRound,
    status: "inactive",
    version: "9.5",
    settings: {
      enabled: false,
      timeout: 600,
      threads: 4,
      service: "ssh"
    }
  },
  {
    id: "ffuf",
    name: "ffuf",
    icon: Terminal,
    status: "inactive",
    version: "2.1.0",
    settings: {
      enabled: false,
      timeout: 180,
      threads: 10
    }
  },
  {
    id: "xsstrike",
    name: "XSStrike",
    icon: Bug,
    status: "inactive",
    version: "3.1.5",
    settings: {
      enabled: false,
      timeout: 180,
      depth: 2
    }
  },
  {
    id: "dalfox",
    name: "Dalfox",
    icon: Sparkles,
    status: "inactive",
    version: "2.9.0",
    settings: {
      enabled: false,
      timeout: 180,
      threads: 10
    }
  },
  {
    id: "testssl",
    name: "testssl.sh",
    icon: ShieldAlert,
    status: "inactive",
    version: "3.2rc3",
    settings: {
      enabled: false,
      timeout: 240
    }
  },
  {
    id: "securityheaders",
    name: "SecurityHeaders.com",
    icon: Shield,
    status: "inactive",
    version: "1.0.0",
    settings: {
      enabled: false,
      timeout: 60
    }
  },
  {
    id: "wpscan",
    name: "WPScan",
    icon: Fingerprint,
    status: "inactive",
    version: "3.8.25",
    settings: {
      enabled: false,
      timeout: 300,
      enumerate: "vp,vt"
    }
  },
  {
    id: "nmap",
    name: "Nmap",
    icon: Server,
    status: "inactive",
    version: "7.94",
    settings: {
      enabled: false,
      timeout: 180,
      ports: "common"
    }
  },
  {
    id: "metasploit",
    name: "Metasploit",
    icon: Skull,
    status: "inactive",
    version: "6.3.50",
    settings: {
      enabled: false,
      timeout: 600
    }
  }
];

export default function Settings() {
  const [tools, setTools] = useState<ToolConfig[]>(toolConfigs);
  const [notifications, setNotifications] = useState({
    scanComplete: true,
    vulnerabilityFound: true,
    systemUpdates: false,
    emailReports: true
  });
  const [scanDefaults, setScanDefaults] = useState({
    maxConcurrent: 3,
    defaultTimeout: 300,
    retryAttempts: 2,
    reportFormat: "pdf"
  });
  const { toast } = useToast();

  // Load saved settings on mount
  useEffect(() => {
    const savedTools = localStorage.getItem("owasp_shield_settings_tools");
    if (savedTools) {
      try {
        const parsed = JSON.parse(savedTools);
        const merged = toolConfigs.map(def => {
          const saved = parsed.find((p: any) => p.id === def.id);
          if (saved) {
            return {
              ...def,
              status: saved.status || def.status,
              settings: {
                ...def.settings,
                ...saved.settings
              }
            };
          }
          return def;
        });
        setTools(merged);
      } catch (e) {
        console.error("Failed to parse saved tools settings:", e);
      }
    }

    const savedNotifications = localStorage.getItem("owasp_shield_settings_notifications");
    if (savedNotifications) {
      try {
        setNotifications(JSON.parse(savedNotifications));
      } catch (e) {
        console.error("Failed to parse notifications settings:", e);
      }
    }

    const savedDefaults = localStorage.getItem("owasp_shield_settings_defaults");
    if (savedDefaults) {
      try {
        setScanDefaults(JSON.parse(savedDefaults));
      } catch (e) {
        console.error("Failed to parse default scan settings:", e);
      }
    }
  }, []);

  const updateToolSetting = (toolId: string, setting: string, value: any) => {
    setTools(tools.map(tool => {
      if (tool.id === toolId) {
        const updatedSettings = { ...tool.settings, [setting]: value };
        return {
          ...tool,
          settings: updatedSettings,
          status: updatedSettings.enabled ? "active" : "inactive"
        };
      }
      return tool;
    }));
  };

  const saveSettings = () => {
    localStorage.setItem("owasp_shield_settings_tools", JSON.stringify(tools));
    localStorage.setItem("owasp_shield_settings_notifications", JSON.stringify(notifications));
    localStorage.setItem("owasp_shield_settings_defaults", JSON.stringify(scanDefaults));
    toast({
      title: "Settings Saved",
      description: "Your configuration has been updated successfully.",
    });
  };

  const resetSettings = () => {
    localStorage.removeItem("owasp_shield_settings_tools");
    localStorage.removeItem("owasp_shield_settings_notifications");
    localStorage.removeItem("owasp_shield_settings_defaults");
    setTools(toolConfigs);
    setNotifications({
      scanComplete: true,
      vulnerabilityFound: true,
      systemUpdates: false,
      emailReports: true
    });
    setScanDefaults({
      maxConcurrent: 3,
      defaultTimeout: 300,
      retryAttempts: 2,
      reportFormat: "pdf"
    });
    toast({
      title: "Settings Reset",
      description: "All settings have been restored to defaults.",
    });
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <SettingsIcon className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Settings</h1>
          <p className="text-muted-foreground">Configure security scanner tools and preferences</p>
        </div>
      </div>

      <Tabs defaultValue="tools" className="w-full">
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="tools">Security Tools</TabsTrigger>
          <TabsTrigger value="scanning">Scan Defaults</TabsTrigger>
          <TabsTrigger value="notifications">Notifications</TabsTrigger>
          <TabsTrigger value="system">System</TabsTrigger>
        </TabsList>

        <TabsContent value="tools" className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {tools.map((tool) => (
              <Card key={tool.id}>
                <CardHeader>
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <tool.icon className="h-6 w-6 text-primary" />
                      <div>
                        <CardTitle className="text-lg">{tool.name}</CardTitle>
                        <CardDescription>Version {tool.version}</CardDescription>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge 
                        variant={tool.status === "active" ? "default" : "secondary"}
                        className={tool.status === "active" ? "bg-info/10 text-info" : ""}
                      >
                        {tool.status === "active" ? (
                          <CheckCircle className="w-3 h-3 mr-1" />
                        ) : (
                          <AlertTriangle className="w-3 h-3 mr-1" />
                        )}
                        {tool.status}
                      </Badge>
                      <Switch
                        checked={tool.settings.enabled}
                        onCheckedChange={(checked) => 
                          updateToolSetting(tool.id, "enabled", checked)
                        }
                      />
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-4">
                  {tool.id === "zap" && (
                    <>
                      <div className="space-y-2">
                        <Label>Scan Depth</Label>
                        <Slider
                          value={[tool.settings.depth]}
                          onValueChange={(value) => 
                            updateToolSetting(tool.id, "depth", value[0])
                          }
                          max={5}
                          min={1}
                          step={1}
                          className="w-full"
                        />
                        <div className="flex justify-between text-sm text-muted-foreground">
                          <span>Shallow (1)</span>
                          <span>Deep (5)</span>
                        </div>
                      </div>
                      <div className="space-y-2">
                        <Label>Thread Count</Label>
                        <Input
                          type="number"
                          value={tool.settings.threads}
                          onChange={(e) => 
                            updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                          }
                        />
                      </div>
                    </>
                  )}
                  
                  {tool.id === "sqlmap" && (
                    <>
                      <div className="space-y-2">
                        <Label>Risk Level</Label>
                        <Select
                          value={tool.settings.risk.toString()}
                          onValueChange={(value) => 
                            updateToolSetting(tool.id, "risk", parseInt(value))
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1">Low (1)</SelectItem>
                            <SelectItem value="2">Medium (2)</SelectItem>
                            <SelectItem value="3">High (3)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Detection Level</Label>
                        <Slider
                          value={[tool.settings.level]}
                          onValueChange={(value) => 
                            updateToolSetting(tool.id, "level", value[0])
                          }
                          max={5}
                          min={1}
                          step={1}
                          className="w-full"
                        />
                      </div>
                    </>
                  )}

                  {tool.id === "nikto" && (
                    <div className="space-y-2">
                      <Label>User Agent</Label>
                      <Input
                        value={tool.settings.useragent}
                        onChange={(e) => 
                          updateToolSetting(tool.id, "useragent", e.target.value)
                        }
                      />
                    </div>
                  )}

                  {tool.id === "subfinder" && (
                    <div className="space-y-2">
                      <Label>Thread Count</Label>
                      <Input
                        type="number"
                        value={tool.settings.threads}
                        onChange={(e) => 
                          updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                        }
                      />
                    </div>
                  )}

                  {tool.id === "gobuster" && (
                    <>
                      <div className="space-y-2">
                        <Label>Thread Count</Label>
                        <Input
                          type="number"
                          value={tool.settings.threads}
                          onChange={(e) => 
                            updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Wordlist</Label>
                        <Select
                          value={tool.settings.wordlist}
                          onValueChange={(value) => 
                            updateToolSetting(tool.id, "wordlist", value)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="common.txt">Common (common.txt)</SelectItem>
                            <SelectItem value="directory-list-2.3-medium.txt">Medium (2.3-medium.txt)</SelectItem>
                            <SelectItem value="big.txt">Large (big.txt)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </>
                  )}

                  {tool.id === "wapiti" && (
                    <div className="space-y-2">
                      <Label>Crawl Depth</Label>
                      <Slider
                        value={[tool.settings.depth]}
                        onValueChange={(value) => 
                          updateToolSetting(tool.id, "depth", value[0])
                        }
                        max={5}
                        min={1}
                        step={1}
                        className="w-full"
                      />
                      <div className="flex justify-between text-sm text-muted-foreground">
                        <span>Shallow (1)</span>
                        <span>Deep (5)</span>
                      </div>
                    </div>
                  )}

                  {tool.id === "nuclei" && (
                    <div className="space-y-2">
                      <Label>Severity Levels (comma separated)</Label>
                      <Input
                        value={tool.settings.severity}
                        onChange={(e) => 
                          updateToolSetting(tool.id, "severity", e.target.value)
                        }
                      />
                    </div>
                  )}

                  {tool.id === "hydra" && (
                    <>
                      <div className="space-y-2">
                        <Label>Thread Count</Label>
                        <Input
                          type="number"
                          value={tool.settings.threads}
                          onChange={(e) => 
                            updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                          }
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Target Service</Label>
                        <Select
                          value={tool.settings.service}
                          onValueChange={(value) => 
                            updateToolSetting(tool.id, "service", value)
                          }
                        >
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="ssh">SSH</SelectItem>
                            <SelectItem value="ftp">FTP</SelectItem>
                            <SelectItem value="http-post-form">HTTP-POST-FORM</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </>
                  )}

                  {tool.id === "ffuf" && (
                    <div className="space-y-2">
                      <Label>Thread Count</Label>
                      <Input
                        type="number"
                        value={tool.settings.threads}
                        onChange={(e) => 
                          updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                        }
                      />
                    </div>
                  )}

                  {tool.id === "xsstrike" && (
                    <div className="space-y-2">
                      <Label>Crawl Depth</Label>
                      <Slider
                        value={[tool.settings.depth]}
                        onValueChange={(value) => 
                          updateToolSetting(tool.id, "depth", value[0])
                        }
                        max={5}
                        min={1}
                        step={1}
                        className="w-full"
                      />
                      <div className="flex justify-between text-sm text-muted-foreground">
                        <span>Shallow (1)</span>
                        <span>Deep (5)</span>
                      </div>
                    </div>
                  )}

                  {tool.id === "dalfox" && (
                    <div className="space-y-2">
                      <Label>Thread Count</Label>
                      <Input
                        type="number"
                        value={tool.settings.threads}
                        onChange={(e) => 
                          updateToolSetting(tool.id, "threads", parseInt(e.target.value))
                        }
                      />
                    </div>
                  )}

                  {tool.id === "wpscan" && (
                    <div className="space-y-2">
                      <Label>Enumeration Target</Label>
                      <Select
                        value={tool.settings.enumerate}
                        onValueChange={(value) => 
                          updateToolSetting(tool.id, "enumerate", value)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="vp,vt">Vulnerable Plugins & Themes</SelectItem>
                          <SelectItem value="u">User Enumeration</SelectItem>
                          <SelectItem value="vp,vt,u">Full Enumeration (Plugins, Themes, Users)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  {tool.id === "nmap" && (
                    <div className="space-y-2">
                      <Label>Port Scanning Mode</Label>
                      <Select
                        value={tool.settings.ports}
                        onValueChange={(value) => 
                          updateToolSetting(tool.id, "ports", value)
                        }
                      >
                        <SelectTrigger>
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="common">Common Ports (Top 1000)</SelectItem>
                          <SelectItem value="fast">Fast Scan (Top 100)</SelectItem>
                          <SelectItem value="full">Full Scan (All 65535)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  )}

                  <div className="space-y-2">
                    <Label>Timeout (seconds)</Label>
                    <Input
                      type="number"
                      value={tool.settings.timeout}
                      onChange={(e) => 
                        updateToolSetting(tool.id, "timeout", parseInt(e.target.value))
                      }
                    />
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="scanning" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Scan Configuration</CardTitle>
              <CardDescription>Default settings for security scans</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div className="space-y-2">
                  <Label>Max Concurrent Scans</Label>
                  <Slider
                    value={[scanDefaults.maxConcurrent]}
                    onValueChange={(value) => 
                      setScanDefaults({...scanDefaults, maxConcurrent: value[0]})
                    }
                    max={10}
                    min={1}
                    step={1}
                    className="w-full"
                  />
                  <p className="text-sm text-muted-foreground">
                    Currently: {scanDefaults.maxConcurrent} concurrent scans
                  </p>
                </div>

                <div className="space-y-2">
                  <Label>Default Timeout (seconds)</Label>
                  <Input
                    type="number"
                    value={scanDefaults.defaultTimeout}
                    onChange={(e) => 
                      setScanDefaults({...scanDefaults, defaultTimeout: parseInt(e.target.value)})
                    }
                  />
                </div>

                <div className="space-y-2">
                  <Label>Retry Attempts</Label>
                  <Select
                    value={scanDefaults.retryAttempts.toString()}
                    onValueChange={(value) => 
                      setScanDefaults({...scanDefaults, retryAttempts: parseInt(value)})
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="0">No retries</SelectItem>
                      <SelectItem value="1">1 retry</SelectItem>
                      <SelectItem value="2">2 retries</SelectItem>
                      <SelectItem value="3">3 retries</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Default Report Format</Label>
                  <Select
                    value={scanDefaults.reportFormat}
                    onValueChange={(value) => 
                      setScanDefaults({...scanDefaults, reportFormat: value})
                    }
                  >
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="pdf">PDF</SelectItem>
                      <SelectItem value="html">HTML</SelectItem>
                      <SelectItem value="json">JSON</SelectItem>
                      <SelectItem value="csv">CSV</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="notifications" className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Notification Preferences</CardTitle>
              <CardDescription>Configure when and how you receive notifications</CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Scan Completion</Label>
                    <p className="text-sm text-muted-foreground">
                      Notify when security scans complete
                    </p>
                  </div>
                  <Switch
                    checked={notifications.scanComplete}
                    onCheckedChange={(checked) => 
                      setNotifications({...notifications, scanComplete: checked})
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Vulnerability Detection</Label>
                    <p className="text-sm text-muted-foreground">
                      Alert when critical vulnerabilities are found
                    </p>
                  </div>
                  <Switch
                    checked={notifications.vulnerabilityFound}
                    onCheckedChange={(checked) => 
                      setNotifications({...notifications, vulnerabilityFound: checked})
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>System Updates</Label>
                    <p className="text-sm text-muted-foreground">
                      Notify about tool updates and system maintenance
                    </p>
                  </div>
                  <Switch
                    checked={notifications.systemUpdates}
                    onCheckedChange={(checked) => 
                      setNotifications({...notifications, systemUpdates: checked})
                    }
                  />
                </div>

                <div className="flex items-center justify-between">
                  <div className="space-y-0.5">
                    <Label>Email Reports</Label>
                    <p className="text-sm text-muted-foreground">
                      Automatically email scan reports to stakeholders
                    </p>
                  </div>
                  <Switch
                    checked={notifications.emailReports}
                    onCheckedChange={(checked) => 
                      setNotifications({...notifications, emailReports: checked})
                    }
                  />
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="system" className="space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>System Information</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label>Application Version</Label>
                  <p className="text-sm font-mono">2.1.0</p>
                </div>
                <div className="space-y-2">
                  <Label>Database Version</Label>
                  <p className="text-sm font-mono">SQLite 3.40.1</p>
                </div>
                <div className="space-y-2">
                  <Label>Last Update Check</Label>
                  <p className="text-sm">January 15, 2024 at 2:30 PM</p>
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Data Management</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button variant="outline" className="w-full">
                  <Database className="mr-2 h-4 w-4" />
                  Export Scan Data
                </Button>
                <Button variant="outline" className="w-full">
                  <Wrench className="mr-2 h-4 w-4" />
                  Check for Updates
                </Button>
                <Button variant="destructive" className="w-full">
                  Clear All Data
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      <div className="flex justify-end gap-4 pt-6 border-t">
        <Button variant="outline" onClick={resetSettings}>
          Reset to Defaults
        </Button>
        <Button onClick={saveSettings}>
          Save Settings
        </Button>
      </div>
    </div>
  );
}