'use client'

import { useState } from 'react'
import { FileText, Download, FileJson, FileCode, File, Loader2 } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

const reports = [
  { Name: 'Full Scan Report', Format: 'HTML', Date: '2024-01-15', Size: '2.3 MB' },
  { Name: 'Executive Summary', Format: 'PDF', Date: '2024-01-14', Size: '450 KB' },
  { Name: 'Compliance Report - PCI', Format: 'JSON', Date: '2024-01-13', Size: '120 KB' },
]

const scanOptions = [
  'Full Scan - Production',
  'Quick Scan - Dev',
  'API Security Scan',
  'Auth Test',
]

export function Reports() {
  const [selectedScan, setSelectedScan] = useState(scanOptions[0])
  const [isGenerating, setIsGenerating] = useState(false)
  const [generatedReport, setGeneratedReport] = useState(false)

  const handleGenerateReport = async () => {
    setIsGenerating(true)
    setGeneratedReport(false)
    
    // Simulate report generation
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    setIsGenerating(false)
    setGeneratedReport(true)
  }

  const getFormatIcon = (format: string) => {
    switch (format) {
      case 'JSON':
        return <FileJson className="h-5 w-5" />
      case 'HTML':
        return <FileCode className="h-5 w-5" />
      case 'PDF':
        return <File className="h-5 w-5" />
      default:
        return <FileText className="h-5 w-5" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-3xl font-bold">Reports</h1>
        <p className="text-muted-foreground mt-1">Generate and download security reports</p>
      </div>

      {/* Generate Report Section */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Generate Report</h2>
        
        <div className="flex items-end gap-4 mb-6">
          <div className="flex-1">
            <label className="block text-sm font-medium mb-2">Select Scan</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
            >
              {scanOptions.map(scan => (
                <option key={scan} value={scan}>{scan}</option>
              ))}
            </select>
          </div>
          <button
            onClick={handleGenerateReport}
            disabled={isGenerating}
            className="flex items-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
          >
            {isGenerating ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileText className="h-4 w-4" />
                Generate Executive Report
              </>
            )}
          </button>
        </div>

        {/* Generated Report Summary */}
        {generatedReport && (
          <div className="border-t pt-6 mt-6">
            <h3 className="font-semibold mb-4">Report Summary</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold">72/100</p>
                <p className="text-sm text-muted-foreground">Risk Score</p>
                <p className="text-xs text-orange-500 mt-1">High</p>
              </div>
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold text-red-500">3</p>
                <p className="text-sm text-muted-foreground">Critical Issues</p>
                <p className="text-xs text-green-500 mt-1">-1 from last scan</p>
              </div>
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold">~2 days</p>
                <p className="text-sm text-muted-foreground">Remediation Time</p>
              </div>
            </div>
            <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg">
              <p className="text-green-500 text-sm">Executive report generated successfully!</p>
            </div>
          </div>
        )}
      </div>

      {/* Download Report Formats */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Download Reports</h2>
        
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
          <button className="flex flex-col items-center gap-2 p-4 border rounded-xl hover:bg-muted transition-colors">
            <FileJson className="h-8 w-8 text-blue-500" />
            <span className="text-sm font-medium">JSON</span>
          </button>
          <button className="flex flex-col items-center gap-2 p-4 border rounded-xl hover:bg-muted transition-colors">
            <FileCode className="h-8 w-8 text-orange-500" />
            <span className="text-sm font-medium">HTML</span>
          </button>
          <button className="flex flex-col items-center gap-2 p-4 border rounded-xl hover:bg-muted transition-colors">
            <FileText className="h-8 w-8 text-green-500" />
            <span className="text-sm font-medium">CSV</span>
          </button>
          <button className="flex flex-col items-center gap-2 p-4 border rounded-xl hover:bg-muted transition-colors">
            <FileText className="h-8 w-8 text-purple-500" />
            <span className="text-sm font-medium">SARIF</span>
          </button>
          <button className="flex flex-col items-center gap-2 p-4 border rounded-xl hover:bg-muted transition-colors opacity-50 cursor-not-allowed">
            <File className="h-8 w-8 text-red-500" />
            <span className="text-sm font-medium">PDF</span>
          </button>
        </div>
      </div>

      {/* Report History */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Report History</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left py-3 px-4 font-medium">Name</th>
                <th className="text-left py-3 px-4 font-medium">Format</th>
                <th className="text-left py-3 px-4 font-medium">Date</th>
                <th className="text-left py-3 px-4 font-medium">Size</th>
                <th className="text-left py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((report, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-3">
                      {getFormatIcon(report.Format)}
                      <span className="font-medium">{report.Name}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-1 bg-muted rounded-full text-xs">{report.Format}</span>
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">{formatDate(report.Date)}</td>
                  <td className="py-3 px-4 text-muted-foreground">{report.Size}</td>
                  <td className="py-3 px-4">
                    <button className="flex items-center gap-2 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90">
                      <Download className="h-4 w-4" />
                      Download
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
