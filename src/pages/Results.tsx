import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { 
  AlertTriangle, 
  Shield, 
  Search, 
  FileText,
  ExternalLink,
  ChevronDown,
  ChevronUp,
  Filter,
  Download,
  ChevronLeft,
  ChevronRight
} from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { useToast } from "@/hooks/use-toast";

interface Finding {
  id: string;
  scan_id: string;
  title: string;
  severity: string;
  tool: string;
  owasp_category: string;
  description: string;
  evidence: string;
  recommendation: string;
  affected_url: string;
  parameters: string[];
  cvss_score: number;
  created_at: string;
}

interface ScanData {
  id: string;
  target_url: string;
  status: string;
  created_at: string;
  total_findings: number;
  high_risk_findings: number;
  medium_risk_findings: number;
  low_risk_findings: number;
}

export default function Results() {
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [findings, setFindings] = useState<Finding[]>([]);
  const [scanHistory, setScanHistory] = useState<ScanData[]>([]);
  const [loading, setLoading] = useState(true);
  const [currentPage, setCurrentPage] = useState(1);
  const [totalFindings, setTotalFindings] = useState(0);
  const ITEMS_PER_PAGE = 50;
  const { toast } = useToast();

  useEffect(() => {
    const fetchScanData = async () => {
      try {
        setLoading(true);
        
        // Fetch scan history
        const { data: scans, error: scanError } = await supabase
          .from('scans')
          .select('*')
          .order('created_at', { ascending: false });

        if (scanError) throw scanError;

        setScanHistory(scans || []);

        // SECURITY FIX: Add pagination to findings query - limit 50 per page
        if (scans && scans.length > 0) {
          // First, get total count
          const { count: findingsCount, error: countError } = await supabase
            .from('findings')
            .select('id', { count: 'exact', head: true })
            .in('scan_id', scans.map(scan => scan.id));

          if (countError) throw countError;
          setTotalFindings(findingsCount || 0);

          // Then get paginated results
          const offset = (currentPage - 1) * ITEMS_PER_PAGE;
          const { data: findingsData, error: findingsError } = await supabase
            .from('findings')
            .select('*')
            .in('scan_id', scans.map(scan => scan.id))
            .order('created_at', { ascending: false })
            .range(offset, offset + ITEMS_PER_PAGE - 1);

          if (findingsError) throw findingsError;

          setFindings(findingsData || []);
        }
      } catch (error) {
        console.error('Error fetching scan data:', error);
        toast({
          title: "Error",
          description: "Failed to load scan data. Please try again.",
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    };

    fetchScanData();
  }, [currentPage, toast]);

  const generateReport = async (scanId: string) => {
    try {
      let success = false;
      try {
        const { data, error } = await supabase.functions.invoke('report-generator', {
          body: { scanId, format: 'pdf' }
        });

        if (error) throw error;

        if (data?.downloadUrl) {
          // Create a temporary link to download the file
          const link = document.createElement('a');
          link.href = data.downloadUrl;
          link.download = `security-report-${scanId}.pdf`;
          document.body.appendChild(link);
          link.click();
          document.body.removeChild(link);
          success = true;
        }
      } catch (invokeError) {
        console.warn("Edge function report generator offline, running local fallback:", invokeError);
        
        toast({
          title: "Edge Function Offline",
          description: "Downloading raw findings. Please use the 'Reports' tab for advanced PDF and HTML generation.",
        });

        // Fallback: Fetch findings and download as JSON
        const { data: findingsData, error: findingsError } = await supabase
          .from('findings')
          .select('*')
          .eq('scan_id', scanId);

        if (findingsError) throw findingsError;

        const jsonData = JSON.stringify(findingsData || [], null, 2);
        const blob = new Blob([jsonData], { type: "application/json" });
        const link = document.createElement("a");
        link.href = URL.createObjectURL(blob);
        link.download = `scan-findings-${scanId}-${Date.now()}.json`;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        success = true;
      }

      if (success) {
        toast({
          title: "Report Generated",
          description: "Your security report has been downloaded.",
        });
      }
    } catch (error) {
      console.error('Error generating report:', error);
      toast({
        title: "Error",
        description: "Failed to generate report. Please try again.",
        variant: "destructive",
      });
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "critical";
      case "High": return "high";
      case "Medium": return "medium";
      default: return "low";
    }
  };

  const filteredFindings = findings.filter(finding => {
    const matchesSearch = finding.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (finding.description || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
                         (finding.owasp_category || '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchesSeverity = severityFilter === "all" || finding.severity === severityFilter;
    return matchesSearch && matchesSeverity;
  });

  const criticalCount = findings.filter(f => f.severity === 'Critical').length;
  const highCount = findings.filter(f => f.severity === 'High').length;
  const mediumCount = findings.filter(f => f.severity === 'Medium').length;

  const toggleFinding = (id: string) => {
    setSelectedFinding(selectedFinding === id ? null : id);
  };

  const totalPages = Math.ceil(totalFindings / ITEMS_PER_PAGE);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <AlertTriangle className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Security Results</h1>
          <p className="text-muted-foreground">Review detected vulnerabilities and scan history</p>
        </div>
      </div>

      <Tabs defaultValue="findings" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="findings">Current Findings</TabsTrigger>
          <TabsTrigger value="history">Scan History</TabsTrigger>
        </TabsList>

        <TabsContent value="findings" className="space-y-6">
          {/* Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Total Findings</p>
                    <p className="text-2xl font-bold">{totalFindings}</p>
                  </div>
                  <Shield className="h-8 w-8 text-muted-foreground" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Critical</p>
                    <p className="text-2xl font-bold text-critical">{criticalCount}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-critical" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">High</p>
                    <p className="text-2xl font-bold text-high">{highCount}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-high" />
                </div>
              </CardContent>
            </Card>
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <div>
                    <p className="text-sm font-medium text-muted-foreground">Medium</p>
                    <p className="text-2xl font-bold text-medium">{mediumCount}</p>
                  </div>
                  <AlertTriangle className="h-8 w-8 text-medium" />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Filters */}
          <Card>
            <CardContent className="pt-6">
              <div className="flex flex-col sm:flex-row gap-4">
                <div className="flex-1">
                  <div className="relative">
                    <Search className="absolute left-3 top-3 h-4 w-4 text-muted-foreground" />
                    <Input
                      placeholder="Search findings..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="pl-10"
                    />
                  </div>
                </div>
                <div className="flex gap-2">
                  <Button
                    variant={severityFilter === "all" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSeverityFilter("all")}
                  >
                    All
                  </Button>
                  <Button
                    variant={severityFilter === "Critical" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSeverityFilter("Critical")}
                  >
                    Critical
                  </Button>
                  <Button
                    variant={severityFilter === "High" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSeverityFilter("High")}
                  >
                    High
                  </Button>
                  <Button
                    variant={severityFilter === "Medium" ? "default" : "outline"}
                    size="sm"
                    onClick={() => setSeverityFilter("Medium")}
                  >
                    Medium
                  </Button>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Findings List */}
          <div className="space-y-4">
            {filteredFindings.map((finding) => (
              <Card key={finding.id} className="transition-all duration-200 hover:shadow-scanner">
                <CardHeader className="cursor-pointer" onClick={() => toggleFinding(finding.id)}>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <div className="flex items-center gap-3 mb-2">
                        <Badge variant={getSeverityColor(finding.severity) as any}>
                          {finding.severity}
                        </Badge>
                        <Badge variant="outline">
                          {finding.owasp_category}
                        </Badge>
                        <Badge variant="outline">
                          {finding.tool}
                        </Badge>
                        {finding.cvss_score && (
                          <Badge variant="outline">
                            CVSS: {finding.cvss_score}
                          </Badge>
                        )}
                      </div>
                      <CardTitle className="text-lg">{finding.title}</CardTitle>
                      <CardDescription>{finding.description}</CardDescription>
                    </div>
                    <Button variant="ghost" size="sm">
                      {selectedFinding === finding.id ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </Button>
                  </div>
                </CardHeader>
                
                {selectedFinding === finding.id && (
                  <CardContent className="border-t border-border space-y-4">
                    {finding.affected_url && (
                      <div>
                        <h4 className="font-semibold mb-2">Affected URL</h4>
                        <div className="flex items-center gap-2">
                          <code className="px-2 py-1 bg-muted rounded text-sm">{finding.affected_url}</code>
                          <Button variant="ghost" size="sm">
                            <ExternalLink className="h-4 w-4" />
                          </Button>
                        </div>
                      </div>
                    )}
                    
                    {finding.evidence && (
                      <div>
                        <h4 className="font-semibold mb-2">Technical Evidence</h4>
                        <pre className="bg-muted p-3 rounded text-sm overflow-auto">
                          {finding.evidence}
                        </pre>
                      </div>
                    )}
                    
                    {finding.recommendation && (
                      <div>
                        <h4 className="font-semibold mb-2">Recommendation</h4>
                        <p className="text-sm text-muted-foreground">{finding.recommendation}</p>
                      </div>
                    )}
                    
                    {finding.parameters && finding.parameters.length > 0 && (
                      <div>
                        <h4 className="font-semibold mb-2">Vulnerable Parameters</h4>
                        <div className="flex gap-2">
                          {finding.parameters.map((param, index) => (
                            <Badge key={index} variant="outline">{param}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                )}
              </Card>
            ))}

            {/* SECURITY FIX: Add pagination controls */}
            {filteredFindings.length === 0 && (
              <div className="text-center py-8">
                <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                <p className="text-muted-foreground">No findings match your filters.</p>
              </div>
            )}
          </div>

          {/* Pagination Controls */}
          {totalFindings > ITEMS_PER_PAGE && (
            <Card>
              <CardContent className="pt-6">
                <div className="flex items-center justify-between">
                  <p className="text-sm text-muted-foreground">
                    Page {currentPage} of {totalPages} ({totalFindings} total findings)
                  </p>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                      disabled={currentPage === 1}
                    >
                      <ChevronLeft className="h-4 w-4 mr-2" />
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setCurrentPage(prev => Math.min(totalPages, prev + 1))}
                      disabled={currentPage === totalPages}
                    >
                      Next
                      <ChevronRight className="h-4 w-4 ml-2" />
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        <TabsContent value="history" className="space-y-6">
          {loading ? (
            <div className="text-center py-8">
              <p className="text-muted-foreground">Loading scan history...</p>
            </div>
          ) : scanHistory.length === 0 ? (
            <div className="text-center py-8">
              <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
              <p className="text-muted-foreground">No scans found. Start your first security scan to see results here.</p>
            </div>
          ) : (
            <div className="space-y-4">
              {scanHistory.map((scan) => (
                <Card key={scan.id}>
                  <CardHeader>
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg">{scan.target_url}</CardTitle>
                        <CardDescription>{new Date(scan.created_at).toLocaleString()}</CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="bg-info/10 text-info">
                          {scan.status}
                        </Badge>
                        <Button 
                          variant="outline" 
                          size="sm"
                          onClick={() => generateReport(scan.id)}
                        >
                          <Download className="mr-2 h-4 w-4" />
                          Download Report
                        </Button>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="grid grid-cols-4 gap-4 text-center">
                      <div>
                        <p className="text-sm text-muted-foreground">Total</p>
                        <p className="text-2xl font-bold">{scan.total_findings || 0}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">High</p>
                        <p className="text-2xl font-bold text-high">{scan.high_risk_findings || 0}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Medium</p>
                        <p className="text-2xl font-bold text-medium">{scan.medium_risk_findings || 0}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Low</p>
                        <p className="text-2xl font-bold text-low">{scan.low_risk_findings || 0}</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}