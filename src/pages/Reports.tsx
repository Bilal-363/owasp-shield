import { useState, useEffect } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { 
  FileText, 
  Download, 
  Eye, 
  Mail,
  Calendar,
  BarChart3,
  Shield,
  TrendingUp,
  ChevronLeft,
  ChevronRight
} from "lucide-react";
import { useToast } from "@/hooks/use-toast";
import { supabase } from "@/integrations/supabase/client";
import { escapeHtml } from "@/lib/utils";
import jsPDF from 'jspdf';
// FIX #3: Removed html2canvas — PDF is now generated with proper text-based jsPDF

interface ScanData {
  id: string;
  target_url: string;
  created_at: string;
  total_findings: number;
  high_risk_findings: number;
  medium_risk_findings: number;
  low_risk_findings: number;
  status: string;
}

interface Finding {
  id: string;
  title: string;
  severity: string;
  tool: string;
  owasp_category: string;
  description: string;
  affected_url: string;
  recommendation: string;
  cvss_score: number;
}

const reportTemplates = [
  {
    id: "executive",
    name: "Executive Summary",
    description: "High-level overview for management and stakeholders",
    features: ["Risk summary", "Business impact", "Compliance status", "Recommendations"]
  },
  {
    id: "technical",
    name: "Technical Report", 
    description: "Detailed technical findings for security teams",
    features: ["Full vulnerability details", "Evidence", "Remediation steps", "OWASP mapping"]
  },
  {
    id: "compliance",
    name: "Compliance Report",
    description: "Structured report for regulatory requirements",
    features: ["Compliance mapping", "Risk ratings", "Control gaps", "Remediation timeline"]
  }
];

export default function Reports() {
  const [selectedScans, setSelectedScans] = useState<string[]>([]);
  const [reportFormat, setReportFormat] = useState("pdf");
  const [reportTemplate, setReportTemplate] = useState("executive");
  const [availableReports, setAvailableReports] = useState<ScanData[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [previewContent, setPreviewContent] = useState<string>("");
  const [currentPage, setCurrentPage] = useState(1);
  const [totalScans, setTotalScans] = useState(0);
  const ITEMS_PER_PAGE = 50;
  const { toast } = useToast();

  useEffect(() => {
    const fetchReportData = async () => {
      try {
        setLoading(true);
        
        // SECURITY FIX: Get total count first
        const { count: scansCount, error: countError } = await supabase
          .from('scans')
          .select('id', { count: 'exact', head: true })
          .eq('status', 'completed');

        if (countError) throw countError;
        setTotalScans(scansCount || 0);

        // SECURITY FIX: Add pagination for scans
        const offset = (currentPage - 1) * ITEMS_PER_PAGE;
        const { data: scans, error: scanError } = await supabase
          .from('scans')
          .select('*')
          .eq('status', 'completed')
          .order('created_at', { ascending: false })
          .range(offset, offset + ITEMS_PER_PAGE - 1);

        if (scanError) throw scanError;

        setAvailableReports(scans || []);

        // Fetch findings for displayed scans
        if (scans && scans.length > 0) {
          const { data: findingsData, error: findingsError } = await supabase
            .from('findings')
            .select('*')
            .in('scan_id', scans.map(scan => scan.id));

          if (findingsError) throw findingsError;

          setFindings(findingsData || []);
        }
      } catch (error) {
        console.error('Error fetching report data:', error);
        toast({
          title: "Error",
          description: "Failed to load report data. Please try again.",
          variant: "destructive",
        });
      } finally {
        setLoading(false);
      }
    };

    fetchReportData();
  }, [currentPage, toast]);

  const handleScanSelection = (scanId: string, checked: boolean) => {
    if (checked) {
      setSelectedScans([...selectedScans, scanId]);
    } else {
      setSelectedScans(selectedScans.filter(id => id !== scanId));
    }
  };

const generateHTMLContent = (scans: ScanData[], findings: Finding[]) => {
  const selectedScanData = scans.filter(scan => selectedScans.includes(scan.id));
  const selectedFindings = findings.filter(finding => {
    const findingScanId = (finding as any).scan_id;
    return selectedScans.includes(findingScanId);
  });

  const totalFindings = selectedFindings.length;
  const criticalCount = selectedFindings.filter(f => f.severity === 'Critical').length;
  const highCount = selectedFindings.filter(f => f.severity === 'High').length;
  const mediumCount = selectedFindings.filter(f => f.severity === 'Medium').length;
  const lowCount = selectedFindings.filter(f => f.severity === 'Low').length;

  return `
    <div style="font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px;
      background: #000; color: #00ffff;">
      
      <h1 style="color: #00ffff; border-bottom: 2px solid #333; padding-bottom: 10px;">
        Security Assessment Report
      </h1>
      
      <div style="margin: 20px 0;">
        <h2 style="color:#00ffff;">Executive Summary</h2>
        <p>This report covers security assessments for ${selectedScanData.length} target(s) with a total of ${totalFindings} findings.</p>
      </div>

      <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 20px 0;">
        <div style="background: #111; padding: 15px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: #00ffff;">Total Findings</h3>
          <p style="font-size: 24px; font-weight: bold; margin: 5px 0;">${totalFindings}</p>
        </div>
        <div style="background: #330000; padding: 15px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: #ff4d4d;">Critical</h3>
          <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #ff4d4d;">${criticalCount}</p>
        </div>
        <div style="background: #332200; padding: 15px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: #ffaa00;">High</h3>
          <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #ffaa00;">${highCount}</p>
        </div>
        <div style="background: #332b00; padding: 15px; border-radius: 8px; text-align: center;">
          <h3 style="margin: 0; color: #ff8800;">Medium</h3>
          <p style="font-size: 24px; font-weight: bold; margin: 5px 0; color: #ff8800;">${mediumCount}</p>
        </div>
      </div>

      <div style="margin: 30px 0;">
        <h2 style="color:#00ffff;">Scanned Targets</h2>
        ${selectedScanData.map(scan => `
          <div style="border: 1px solid #333; padding: 15px; margin: 10px 0; border-radius: 8px; background:#111;">
            <h3 style="margin: 0 0 10px 0; color:#00ffff;">${escapeHtml(scan.target_url)}</h3>
            <p style="color: #aaa; margin: 5px 0;">Scanned: ${new Date(scan.created_at).toLocaleString()}</p>
            <p style="margin: 5px 0;">Status: <span style="color: #16a34a; font-weight: bold;">${escapeHtml(scan.status)}</span></p>
          </div>
        `).join('')}
      </div>

      <div style="margin: 30px 0;">
        <h2 style="color:#00ffff;">Detailed Findings by Tool</h2>
        ${selectedFindings.length === 0 ? '<p style="color: #aaa;">No vulnerabilities or findings reported for the selected scans.</p>' : ''}
        ${Object.entries(
          selectedFindings.reduce((acc: any, finding: Finding) => {
            const t = finding.tool || 'Unknown';
            if (!acc[t]) acc[t] = [];
            acc[t].push(finding);
            return acc;
          }, {})
        ).map(([toolName, toolFindings]: [string, any]) => `
          <div style="margin-top: 30px; margin-bottom: 20px;">
            <h3 style="color:#ffffff; border-bottom: 1px solid #333; padding-bottom: 5px; text-transform: uppercase;">
              ${escapeHtml(toolName)} Findings
            </h3>
            ${toolFindings.map((finding: Finding) => `
              <div style="border: 1px solid #333; padding: 20px; margin: 15px 0; border-radius: 8px; background:#111;">
                <div style="display: flex; align-items: center; margin-bottom: 10px;">
                  <span style="background: ${
                    finding.severity === 'Critical' ? '#dc2626' :
                    finding.severity === 'High' ? '#d97706' :
                    finding.severity === 'Medium' ? '#ea580c' : '#2563eb'
                  }; color: white; padding: 4px 8px; border-radius: 4px; font-size: 12px; margin-right: 10px;">
                    ${escapeHtml(finding.severity)}
                  </span>
                  <span style="background: #222; color:#00ffff; padding: 4px 8px; border-radius: 4px; font-size: 12px;">
                    ${escapeHtml(finding.owasp_category)}
                  </span>
                </div>
                <h3 style="margin: 10px 0; color:#00ffff;">${escapeHtml(finding.title)}</h3>
                <p style="color: #aaa; margin: 10px 0;">${escapeHtml(finding.description)}</p>
                ${finding.affected_url ? `<p><strong style="color:#00ffff;">Affected URL:</strong> ${escapeHtml(finding.affected_url)}</p>` : ''}
                ${finding.recommendation ? `<div style="background: #001f33; color:#00ffff; padding: 15px; border-radius: 8px; margin: 10px 0;">
                  <strong>Recommendation:</strong> ${escapeHtml(finding.recommendation)}
                </div>` : ''}
              </div>
            `).join('')}
          </div>
        `).join('')}
      </div>
    </div>
  `;
};

const generateWordHTMLContent = (scans: ScanData[], findings: Finding[]) => {
  const selectedScanData = scans.filter(scan => selectedScans.includes(scan.id));
  const selectedFindings = findings.filter(finding => {
    const findingScanId = (finding as any).scan_id;
    return selectedScans.includes(findingScanId);
  });

  const totalFindings = selectedFindings.length;
  const criticalCount = selectedFindings.filter(f => f.severity === 'Critical').length;
  const highCount = selectedFindings.filter(f => f.severity === 'High').length;
  const mediumCount = selectedFindings.filter(f => f.severity === 'Medium').length;
  const lowCount = selectedFindings.filter(f => f.severity === 'Low').length;

  return `
    <div style="font-family: Calibri, Arial, sans-serif; color: #333333; line-height: 1.5; padding: 20px;">
      <h1 style="color: #0c4a6e; font-size: 28px; border-bottom: 2px solid #0c4a6e; padding-bottom: 10px; margin-bottom: 5px;">
        OWASP Security Assessment Report
      </h1>
      <p style="color: #666666; font-size: 12px; margin-top: 0; margin-bottom: 25px;">
        Generated on ${new Date().toLocaleDateString()} by OWASP Shield Desk
      </p>
      
      <div style="margin-bottom: 30px; background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 15px; border-radius: 8px;">
        <h2 style="color: #0f172a; font-size: 20px; margin-top: 0; margin-bottom: 10px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px;">
          Executive Summary
        </h2>
        <p style="font-size: 14px; margin-bottom: 15px;">
          This security assessment report summarizes vulnerability scanning results across <strong>${selectedScanData.length} target(s)</strong>.
          A total of <strong>${totalFindings} security findings</strong> were identified. Please review the details below to plan remediation activities.
        </p>
        
        <table style="width: 100%; border-collapse: collapse; text-align: center; font-size: 14px;">
          <tr>
            <th style="background-color: #f1f5f9; border: 1px solid #cbd5e1; padding: 10px;">Total Findings</th>
            <th style="background-color: #fee2e2; border: 1px solid #cbd5e1; padding: 10px; color: #991b1b;">Critical</th>
            <th style="background-color: #ffedd5; border: 1px solid #cbd5e1; padding: 10px; color: #c2410c;">High</th>
            <th style="background-color: #fef9c3; border: 1px solid #cbd5e1; padding: 10px; color: #854d0e;">Medium</th>
            <th style="background-color: #dbeafe; border: 1px solid #cbd5e1; padding: 10px; color: #1e40af;">Low</th>
          </tr>
          <tr>
            <td style="border: 1px solid #cbd5e1; padding: 10px; font-weight: bold; font-size: 18px;">${totalFindings}</td>
            <td style="border: 1px solid #cbd5e1; padding: 10px; font-weight: bold; font-size: 18px; color: #991b1b;">${criticalCount}</td>
            <td style="border: 1px solid #cbd5e1; padding: 10px; font-weight: bold; font-size: 18px; color: #c2410c;">${highCount}</td>
            <td style="border: 1px solid #cbd5e1; padding: 10px; font-weight: bold; font-size: 18px; color: #854d0e;">${mediumCount}</td>
            <td style="border: 1px solid #cbd5e1; padding: 10px; font-weight: bold; font-size: 18px; color: #1e40af;">${lowCount}</td>
          </tr>
        </table>
      </div>

      <div style="margin-bottom: 30px;">
        <h2 style="color: #0f172a; font-size: 20px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-bottom: 15px;">
          Scanned Targets
        </h2>
        <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
          <thead>
            <tr style="background-color: #f1f5f9; border-bottom: 2px solid #cbd5e1;">
              <th style="text-align: left; padding: 10px; border: 1px solid #e2e8f0;">Target URL</th>
              <th style="text-align: left; padding: 10px; border: 1px solid #e2e8f0;">Scan Time</th>
              <th style="text-align: left; padding: 10px; border: 1px solid #e2e8f0;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${selectedScanData.map(scan => `
              <tr>
                <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; color: #0284c7;">${escapeHtml(scan.target_url)}</td>
                <td style="padding: 10px; border: 1px solid #e2e8f0;">${new Date(scan.created_at).toLocaleString()}</td>
                <td style="padding: 10px; border: 1px solid #e2e8f0; font-weight: bold; color: #16a34a;">${escapeHtml(scan.status)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>

      <div>
        <h2 style="color: #0f172a; font-size: 20px; border-bottom: 1px solid #cbd5e1; padding-bottom: 5px; margin-bottom: 15px;">
          Detailed Security Findings by Tool
        </h2>
        
        ${selectedFindings.length === 0 ? `
          <p style="color: #666666; font-style: italic;">No vulnerabilities or findings reported for the selected scans.</p>
        ` : Object.entries(
          selectedFindings.reduce((acc: any, finding: Finding) => {
            const t = finding.tool || 'Unknown';
            if (!acc[t]) acc[t] = [];
            acc[t].push(finding);
            return acc;
          }, {})
        ).map(([toolName, toolFindings]: [string, any]) => `
          <div style="margin-bottom: 30px;">
            <h3 style="color: #1e293b; font-size: 18px; border-bottom: 1px solid #e2e8f0; padding-bottom: 5px; margin-bottom: 15px; text-transform: uppercase;">
              ${escapeHtml(toolName)} Findings
            </h3>
            ${toolFindings.map((finding: Finding, idx: number) => {
              const sevColor = 
                finding.severity === 'Critical' ? '#991b1b' :
                finding.severity === 'High' ? '#c2410c' :
                finding.severity === 'Medium' ? '#854d0e' : '#1e40af';
              
              const sevBg = 
                finding.severity === 'Critical' ? '#fee2e2' :
                finding.severity === 'High' ? '#ffedd5' :
                finding.severity === 'Medium' ? '#fef9c3' : '#dbeafe';

              return `
                <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px; margin-bottom: 20px; page-break-inside: avoid;">
                  <table style="width: 100%; border-collapse: collapse; margin-bottom: 10px;">
                    <tr>
                      <td>
                        <h4 style="margin: 0; color: #0f172a; font-size: 16px;">
                          ${idx + 1}. ${escapeHtml(finding.title)}
                        </h4>
                      </td>
                      <td style="text-align: right; width: 150px;">
                        <span style="background-color: ${sevBg}; color: ${sevColor}; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 12px; display: inline-block;">
                          ${escapeHtml(finding.severity)}
                        </span>
                      </td>
                    </tr>
                  </table>
                  
                  <table style="width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 10px; background-color: #f8fafc;">
                    <tr>
                      <td style="padding: 6px; width: 120px; font-weight: bold; color: #475569;">OWASP Category:</td>
                      <td style="padding: 6px;">${escapeHtml(finding.owasp_category)}</td>
                    </tr>
                    ${finding.affected_url ? `
                      <tr>
                        <td style="padding: 6px; font-weight: bold; color: #475569;">Affected URL:</td>
                        <td style="padding: 6px; font-family: monospace; color: #0284c7; word-break: break-all;">${escapeHtml(finding.affected_url)}</td>
                      </tr>
                    ` : ''}
                    ${finding.cvss_score ? `
                      <tr>
                        <td style="padding: 6px; font-weight: bold; color: #475569;">CVSS v3 Score:</td>
                        <td style="padding: 6px; font-weight: bold; color: #991b1b;">${escapeHtml(String(finding.cvss_score))}</td>
                      </tr>
                    ` : ''}
                  </table>
                  
                  <p style="font-size: 14px; margin-top: 10px; margin-bottom: 10px; color: #334155;">
                    <strong>Description:</strong><br/>
                    ${escapeHtml(finding.description)}
                  </p>
                  
                  ${finding.recommendation ? `
                    <div style="background-color: #eff6ff; border: 1px solid #bfdbfe; padding: 12px; border-radius: 6px; margin-top: 10px; color: #1e3a8a;">
                      <strong>Remediation Recommendation:</strong><br/>
                      ${escapeHtml(finding.recommendation)}
                    </div>
                  ` : ''}
                </div>
              `;
            }).join('')}
          </div>
        `).join('')}
      </div>
    </div>
  `;
};

 const generateReport = async () => {
  if (selectedScans.length === 0) {
    toast({
      title: "No Scans Selected",
      description: "Please select at least one scan to generate a report.",
      variant: "destructive",
    });
    return;
  }

  try {
    const htmlContent = generateHTMLContent(availableReports, findings);

    if (reportFormat === "pdf") {
      // ================================================================
      // FIX #3: Proper text-based PDF generation using jsPDF
      // ================================================================
      // Old approach: html2canvas screenshot → PNG image embedded in PDF
      //   - Non-selectable text, bloated file size, awkward page breaks
      // New approach: Direct jsPDF text rendering
      //   - Selectable/searchable text, proper page breaks, small file size
      // ================================================================
      const selectedScanData = availableReports.filter(scan => selectedScans.includes(scan.id));
      const selectedFindings = findings.filter(f => selectedScans.includes((f as any).scan_id));

      const pdf = new jsPDF();
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 15;
      const contentWidth = pageWidth - margin * 2;
      let y = margin;

      const severityColors: Record<string, [number, number, number]> = {
        'Critical': [220, 38, 38],
        'High': [217, 119, 6],
        'Medium': [234, 88, 12],
        'Low': [37, 99, 235],
        'Info': [107, 114, 128],
      };

      // Helper: add page footer with page number
      const addFooter = (pageNum: number) => {
        pdf.setFontSize(8);
        pdf.setTextColor(150, 150, 150);
        pdf.text(`OWASP Shield Desk — Security Report — Page ${pageNum}`, pageWidth / 2, pageHeight - 8, { align: 'center' });
        pdf.text('CONFIDENTIAL', pageWidth - margin, pageHeight - 8, { align: 'right' });
      };

      // Helper: check if we need a new page
      const checkPage = (requiredHeight: number) => {
        if (y + requiredHeight > pageHeight - 20) {
          addFooter(pdf.getNumberOfPages());
          pdf.addPage();
          y = margin;
        }
      };

      // ---- Title Page ----
      pdf.setFontSize(28);
      pdf.setTextColor(12, 74, 110);
      pdf.text('Security Assessment', pageWidth / 2, 60, { align: 'center' });
      pdf.text('Report', pageWidth / 2, 75, { align: 'center' });

      pdf.setFontSize(12);
      pdf.setTextColor(100, 100, 100);
      pdf.text(`Generated: ${new Date().toLocaleString()}`, pageWidth / 2, 95, { align: 'center' });
      pdf.text(`Targets: ${selectedScanData.length} | Findings: ${selectedFindings.length}`, pageWidth / 2, 105, { align: 'center' });
      pdf.text('OWASP Shield Desk — Professional Edition', pageWidth / 2, 120, { align: 'center' });

      addFooter(1);
      pdf.addPage();
      y = margin;

      // ---- Executive Summary ----
      pdf.setFontSize(18);
      pdf.setTextColor(12, 74, 110);
      pdf.text('Executive Summary', margin, y);
      y += 10;

      pdf.setDrawColor(12, 74, 110);
      pdf.setLineWidth(0.5);
      pdf.line(margin, y, pageWidth - margin, y);
      y += 8;

      const highCount = selectedFindings.filter(f => f.severity === 'High').length;
      const mediumCount = selectedFindings.filter(f => f.severity === 'Medium').length;
      const lowCount = selectedFindings.filter(f => f.severity === 'Low').length;
      const criticalCount = selectedFindings.filter(f => f.severity === 'Critical').length;

      pdf.setFontSize(11);
      pdf.setTextColor(50, 50, 50);
      const summaryLines = pdf.splitTextToSize(
        `This security assessment report summarizes vulnerability scanning results across ${selectedScanData.length} target(s). A total of ${selectedFindings.length} security findings were identified.`,
        contentWidth
      );
      pdf.text(summaryLines, margin, y);
      y += summaryLines.length * 6 + 8;

      // Summary table
      const colWidth = contentWidth / 5;
      const labels = ['Total', 'Critical', 'High', 'Medium', 'Low'];
      const counts = [selectedFindings.length, criticalCount, highCount, mediumCount, lowCount];
      const bgColors: [number, number, number][] = [
        [241, 245, 249], [254, 226, 226], [255, 237, 213], [254, 249, 195], [219, 234, 254]
      ];

      // Table header
      for (let i = 0; i < labels.length; i++) {
        const x = margin + i * colWidth;
        pdf.setFillColor(...bgColors[i]);
        pdf.rect(x, y, colWidth, 10, 'F');
        pdf.setDrawColor(200, 200, 200);
        pdf.rect(x, y, colWidth, 10, 'S');
        pdf.setFontSize(9);
        pdf.setTextColor(50, 50, 50);
        pdf.text(labels[i], x + colWidth / 2, y + 7, { align: 'center' });
      }
      y += 10;

      // Table values
      for (let i = 0; i < counts.length; i++) {
        const x = margin + i * colWidth;
        pdf.setDrawColor(200, 200, 200);
        pdf.rect(x, y, colWidth, 10, 'S');
        pdf.setFontSize(14);
        pdf.setTextColor(30, 30, 30);
        pdf.text(String(counts[i]), x + colWidth / 2, y + 8, { align: 'center' });
      }
      y += 18;

      // ---- Scanned Targets ----
      checkPage(30);
      pdf.setFontSize(16);
      pdf.setTextColor(12, 74, 110);
      pdf.text('Scanned Targets', margin, y);
      y += 8;
      pdf.setDrawColor(12, 74, 110);
      pdf.line(margin, y, pageWidth - margin, y);
      y += 6;

      for (const scan of selectedScanData) {
        checkPage(18);
        pdf.setFontSize(10);
        pdf.setTextColor(2, 132, 199);
        pdf.text(scan.target_url, margin + 2, y);
        y += 5;
        pdf.setTextColor(100, 100, 100);
        pdf.setFontSize(9);
        pdf.text(`Scanned: ${new Date(scan.created_at).toLocaleString()} | Status: ${scan.status}`, margin + 2, y);
        y += 8;
      }

      // ---- Detailed Findings ----
      checkPage(20);
      y += 5;
      pdf.setFontSize(16);
      pdf.setTextColor(12, 74, 110);
      pdf.text('Detailed Security Findings', margin, y);
      y += 8;
      pdf.setDrawColor(12, 74, 110);
      pdf.line(margin, y, pageWidth - margin, y);
      y += 8;

      if (selectedFindings.length === 0) {
        pdf.setFontSize(11);
        pdf.setTextColor(100, 100, 100);
        pdf.text('No vulnerabilities or findings reported for the selected scans.', margin, y);
        y += 10;
      }

      // Group findings by tool
      const groupedByTool = selectedFindings.reduce((acc: Record<string, Finding[]>, f) => {
        const t = f.tool || 'Unknown';
        if (!acc[t]) acc[t] = [];
        acc[t].push(f);
        return acc;
      }, {});

      for (const [toolName, toolFindings] of Object.entries(groupedByTool)) {
        checkPage(20);
        pdf.setFontSize(13);
        pdf.setTextColor(30, 41, 59);
        pdf.text(`${toolName.toUpperCase()} Findings`, margin, y);
        y += 6;
        pdf.setDrawColor(200, 200, 200);
        pdf.line(margin, y, pageWidth - margin, y);
        y += 6;

        for (let idx = 0; idx < toolFindings.length; idx++) {
          const finding = toolFindings[idx];
          // Estimate block height: title + meta + description + recommendation
          checkPage(55);

          // Severity badge
          const sevColor = severityColors[finding.severity] || [100, 100, 100];
          pdf.setFillColor(...sevColor);
          pdf.roundedRect(margin, y, 22, 6, 1, 1, 'F');
          pdf.setFontSize(8);
          pdf.setTextColor(255, 255, 255);
          pdf.text(finding.severity, margin + 11, y + 4.5, { align: 'center' });

          // OWASP category badge
          pdf.setFillColor(241, 245, 249);
          pdf.roundedRect(margin + 24, y, 55, 6, 1, 1, 'F');
          pdf.setTextColor(71, 85, 105);
          pdf.text(finding.owasp_category || '', margin + 51.5, y + 4.5, { align: 'center' });
          y += 10;

          // Title
          pdf.setFontSize(11);
          pdf.setTextColor(15, 23, 42);
          const titleLines = pdf.splitTextToSize(`${idx + 1}. ${finding.title}`, contentWidth);
          pdf.text(titleLines, margin, y);
          y += titleLines.length * 5 + 3;

          // Description
          if (finding.description) {
            checkPage(15);
            pdf.setFontSize(9);
            pdf.setTextColor(51, 65, 85);
            const descLines = pdf.splitTextToSize(`Description: ${finding.description}`, contentWidth - 4);
            pdf.text(descLines, margin + 2, y);
            y += descLines.length * 4.5 + 3;
          }

          // Affected URL
          if (finding.affected_url) {
            checkPage(10);
            pdf.setFontSize(9);
            pdf.setTextColor(2, 132, 199);
            const urlLines = pdf.splitTextToSize(`Affected URL: ${finding.affected_url}`, contentWidth - 4);
            pdf.text(urlLines, margin + 2, y);
            y += urlLines.length * 4.5 + 2;
          }

          // CVSS Score
          if (finding.cvss_score) {
            pdf.setFontSize(9);
            pdf.setTextColor(153, 27, 27);
            pdf.text(`CVSS v3 Score: ${finding.cvss_score}`, margin + 2, y);
            y += 5;
          }

          // Recommendation
          if (finding.recommendation) {
            checkPage(15);
            pdf.setFillColor(239, 246, 255);
            const recLines = pdf.splitTextToSize(`Recommendation: ${finding.recommendation}`, contentWidth - 8);
            const recHeight = recLines.length * 4.5 + 6;
            pdf.roundedRect(margin, y, contentWidth, recHeight, 2, 2, 'F');
            pdf.setFontSize(9);
            pdf.setTextColor(30, 58, 138);
            pdf.text(recLines, margin + 4, y + 5);
            y += recHeight + 5;
          }

          // Separator between findings
          y += 3;
          pdf.setDrawColor(230, 230, 230);
          pdf.line(margin + 10, y, pageWidth - margin - 10, y);
          y += 6;
        }
      }

      addFooter(pdf.getNumberOfPages());
      pdf.save(`security-report-${Date.now()}.pdf`);

    } else if (reportFormat === "html") {
      // HTML export
      const blob = new Blob([htmlContent], { type: "text/html" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `security-report-${Date.now()}.html`;
      link.click();

    } else if (reportFormat === "doc") {
      // Word document export
      const wordHeader = `
        <html xmlns:o='urn:schemas-microsoft-com:office:office' 
              xmlns:w='urn:schemas-microsoft-com:office:word' 
              xmlns='http://www.w3.org/TR/REC-html40'>
        <head>
          <title>Security Assessment Report</title>
          <!--[if gte mso 9]>
          <xml>
            <w:WordDocument>
              <w:View>Print</w:View>
              <w:Zoom>100</w:Zoom>
              <w:DoNotOptimizeForBrowser/>
            </w:WordDocument>
          </xml>
          <![endif]-->
        </head>
        <body>
      `;
      const wordFooter = "</body></html>";
      const wordContent = generateWordHTMLContent(availableReports, findings);
      const fullDoc = wordHeader + wordContent + wordFooter;
      
      const blob = new Blob(['\ufeff' + fullDoc], { type: "application/msword" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `security-report-${Date.now()}.doc`;
      link.click();

    } else if (reportFormat === "json") {
      // JSON export
      const selectedFindings = findings.filter(f =>
        selectedScans.includes((f as any).scan_id)
      );
      const jsonData = JSON.stringify(selectedFindings, null, 2);
      const blob = new Blob([jsonData], { type: "application/json" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `security-report-${Date.now()}.json`;
      link.click();

    } else if (reportFormat === "csv") {
      // CSV export
      const selectedFindings = findings.filter(f =>
        selectedScans.includes((f as any).scan_id)
      );
      if (selectedFindings.length === 0) throw new Error("No findings to export.");

      const headers = Object.keys(selectedFindings[0]).join(",");
      const rows = selectedFindings.map(f =>
        Object.values(f)
          .map(v => `"${String(v).replace(/"/g, '""')}"`) // escape quotes
          .join(",")
      );
      const csvContent = [headers, ...rows].join("\n");

      const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
      const link = document.createElement("a");
      link.href = URL.createObjectURL(blob);
      link.download = `security-report-${Date.now()}.csv`;
      link.click();
    }

    toast({
      title: "Report Generated",
      description: `${reportTemplate} report (${reportFormat.toUpperCase()}) has been downloaded.`,
    });

  } catch (error) {
    console.error("Error generating report:", error);
    toast({
      title: "Error",
      description: "Failed to generate report. Please try again.",
      variant: "destructive",
    });
  }
};

  const previewReport = () => {
    if (selectedScans.length === 0) {
      toast({
        title: "No Scans Selected", 
        description: "Please select at least one scan to preview.",
        variant: "destructive",
      });
      return;
    }

    const htmlContent = generateHTMLContent(availableReports, findings);
    setPreviewContent(htmlContent);
    setPreviewOpen(true);
  };

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <FileText className="h-8 w-8 text-primary" />
        <div>
          <h1 className="text-3xl font-bold">Security Reports</h1>
          <p className="text-muted-foreground">Generate comprehensive security assessment reports</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Report Configuration */}
        <div className="lg:col-span-2 space-y-6">
          {/* Scan Selection */}
          <Card>
            <CardHeader>
              <CardTitle>Select Scans</CardTitle>
              <CardDescription>Choose which security scans to include in the report</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {loading ? (
                <div className="text-center py-8">
                  <p className="text-muted-foreground">Loading scans...</p>
                </div>
              ) : availableReports.length === 0 ? (
                <div className="text-center py-8">
                  <Shield className="h-12 w-12 mx-auto mb-4 text-muted-foreground" />
                  <p className="text-muted-foreground">No completed scans found. Run some security scans first.</p>
                </div>
              ) : (
                <>
                  {availableReports.map((scan) => (
                    <div key={scan.id} className="flex items-center space-x-3 p-3 border rounded-lg">
                      <Checkbox
                        id={scan.id}
                        checked={selectedScans.includes(scan.id)}
                        onCheckedChange={(checked) => handleScanSelection(scan.id, checked as boolean)}
                      />
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <div>
                            <Label htmlFor={scan.id} className="font-medium cursor-pointer">
                              {scan.target_url}
                            </Label>
                            <p className="text-sm text-muted-foreground flex items-center gap-1">
                              <Calendar className="h-3 w-3" />
                              {new Date(scan.created_at).toLocaleDateString()}
                            </p>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{scan.total_findings || 0} findings</Badge>
                            {scan.high_risk_findings > 0 && (
                              <Badge variant="high">{scan.high_risk_findings} High</Badge>
                            )}
                            {scan.medium_risk_findings > 0 && (
                              <Badge variant="medium">{scan.medium_risk_findings} Medium</Badge>
                            )}
                            {scan.low_risk_findings > 0 && (
                              <Badge variant="low">{scan.low_risk_findings} Low</Badge>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  ))}

                  {/* SECURITY FIX: Pagination controls for scans */}
                  {totalScans > ITEMS_PER_PAGE && (
                    <div className="flex items-center justify-between mt-4 p-3 border rounded-lg bg-muted/50">
                      <p className="text-sm text-muted-foreground">
                        Page {currentPage} of {Math.ceil(totalScans / ITEMS_PER_PAGE)} ({totalScans} total scans)
                      </p>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(prev => Math.max(1, prev - 1))}
                          disabled={currentPage === 1}
                        >
                          <ChevronLeft className="h-4 w-4 mr-1" />
                          Previous
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => setCurrentPage(prev => Math.min(Math.ceil(totalScans / ITEMS_PER_PAGE), prev + 1))}
                          disabled={currentPage === Math.ceil(totalScans / ITEMS_PER_PAGE)}
                        >
                          Next
                          <ChevronRight className="h-4 w-4 ml-1" />
                        </Button>
                      </div>
                    </div>
                  )}
                </>
              )}
            </CardContent>
          </Card>

          {/* Report Templates */}
          <Card>
            <CardHeader>
              <CardTitle>Report Template</CardTitle>
              <CardDescription>Choose the type of report to generate</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {reportTemplates.map((template) => (
                <div 
                  key={template.id}
                  className={`p-4 border rounded-lg cursor-pointer transition-all ${
                    reportTemplate === template.id 
                      ? "border-primary bg-primary/5" 
                      : "hover:border-muted-foreground/50"
                  }`}
                  onClick={() => setReportTemplate(template.id)}
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <h3 className="font-semibold">{template.name}</h3>
                      <p className="text-sm text-muted-foreground mb-2">{template.description}</p>
                      <div className="flex flex-wrap gap-1">
                        {template.features.map((feature, index) => (
                          <Badge key={index} variant="outline" className="text-xs">
                            {feature}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div className={`w-4 h-4 rounded-full border-2 ${
                      reportTemplate === template.id 
                        ? "border-primary bg-primary" 
                        : "border-muted-foreground/50"
                    }`}>
                      {reportTemplate === template.id && (
                        <div className="w-full h-full rounded-full bg-background scale-50" />
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>

        {/* Report Actions */}
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Export Options</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label>Format</Label>
                <Select value={reportFormat} onValueChange={setReportFormat}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="pdf">PDF Document</SelectItem>
                    <SelectItem value="html">HTML Report</SelectItem>
                    <SelectItem value="doc">Word Document (.doc)</SelectItem>
                    <SelectItem value="json">JSON Data</SelectItem>
                    <SelectItem value="csv">CSV Export</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-3 pt-4">
                <Button onClick={previewReport} variant="outline" className="w-full">
                  <Eye className="mr-2 h-4 w-4" />
                  Preview Report
                </Button>
                
                <Button onClick={generateReport} className="w-full">
                  <Download className="mr-2 h-4 w-4" />
                  Generate Report
                </Button>
                
                <Button variant="outline" className="w-full">
                  <Mail className="mr-2 h-4 w-4" />
                  Email Report
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Report Statistics */}
          <Card>
            <CardHeader>
              <CardTitle>Report Statistics</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-center">
                <div>
                  <Shield className="h-8 w-8 mx-auto mb-2 text-primary" />
                  <p className="text-2xl font-bold">{availableReports.length}</p>
                  <p className="text-xs text-muted-foreground">Total Scans</p>
                </div>
                <div>
                  <BarChart3 className="h-8 w-8 mx-auto mb-2 text-high" />
                  <p className="text-2xl font-bold">{findings.length}</p>
                  <p className="text-xs text-muted-foreground">Total Findings</p>
                </div>
              </div>
              
              <div className="border-t pt-4">
                <div className="flex items-center gap-2 text-sm">
                  <TrendingUp className="h-4 w-4 text-info" />
                  <span className="text-muted-foreground">
                    {availableReports.length > 0 
                      ? `Last scan: ${new Date(availableReports[0]?.created_at).toLocaleDateString()}`
                      : 'No scans available'
                    }
                  </span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Preview Dialog */}
      <Dialog open={previewOpen} onOpenChange={setPreviewOpen}>
        <DialogContent className="max-w-4xl max-h-[80vh] overflow-auto">
          <DialogHeader>
            <DialogTitle>Report Preview</DialogTitle>
          </DialogHeader>
          <div 
            dangerouslySetInnerHTML={{ __html: previewContent }}
            className="prose max-w-none"
          />
        </DialogContent>
      </Dialog>
    </div>
  );
}
