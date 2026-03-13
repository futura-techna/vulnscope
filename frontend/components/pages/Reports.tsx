'use client'

import { useState } from 'react'
import { FileText, Download, FileJson, FileCode, File, Loader2, RefreshCw, CheckCircle, ExternalLink } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useReports, useGenerateReport, useScans } from '@/lib/hooks/useApi'
import api from '@/lib/api'

// Sample report for demo/download when backend is not available
const SAMPLE_REPORT = {
  id: 'demo-report-001',
  name: 'Security Scan Report - maths-plus-plus.vercel.app',
  format: 'html',
  size: '12.9 KB',
  created_at: new Date().toISOString(),
  scan_id: 'demo-scan',
  download_url: '/vulnscope_report.html'
}

export function Reports() {
  const [selectedScan, setSelectedScan] = useState('')
  const [selectedFormat, setSelectedFormat] = useState('html')
  const [reportName, setReportName] = useState('')
  const [generatedReport, setGeneratedReport] = useState<any>(null)
  const [isDownloading, setIsDownloading] = useState(false)

  // Fetch data using React Query hooks
  const { data: reports, isLoading: reportsLoading, refetch: refetchReports } = useReports()
  const { data: scans, isLoading: scansLoading } = useScans()
  const generateReport = useGenerateReport()

  const isLoading = reportsLoading || scansLoading

  const handleGenerateReport = async () => {
    if (!selectedScan) {
      alert('Please select a scan first')
      return
    }

    try {
      const result = await generateReport.mutateAsync({
        scan_id: selectedScan,
        name: reportName || `Report for ${scans?.find(s => s.id === selectedScan)?.name || 'Scan'}`,
        format: selectedFormat,
      })
      setGeneratedReport(result)
    } catch (error) {
      console.error('Failed to generate report:', error)
      alert('Failed to generate report. Please try again.')
    }
  }

  const getFormatIcon = (format: string) => {
    switch (format.toLowerCase()) {
      case 'json':
        return <FileJson className="h-5 w-5" />
      case 'html':
        return <FileCode className="h-5 w-5" />
      case 'pdf':
        return <File className="h-5 w-5" />
      case 'csv':
        return <FileText className="h-5 w-5" />
      case 'sarif':
        return <FileCode className="h-5 w-5" />
      default:
        return <FileText className="h-5 w-5" />
    }
  }

  const formats = [
    { id: 'json', name: 'JSON', icon: FileJson, color: 'text-blue-500' },
    { id: 'html', name: 'HTML', icon: FileCode, color: 'text-orange-500' },
    { id: 'csv', name: 'CSV', icon: FileText, color: 'text-green-500' },
    { id: 'sarif', name: 'SARIF', icon: FileCode, color: 'text-purple-500' },
    { id: 'pdf', name: 'PDF', icon: File, color: 'text-red-500' },
  ]

  const handleDownloadReport = async (reportId: string, format: string) => {
    try {
      const blob = await api.downloadReport(reportId)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      // Determine file extension based on format
      let extension = format.toLowerCase()
      if (extension === 'sarif') {
        extension = 'sarif.json'
      }
      a.download = `vulnscope-report-${reportId}.${extension}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (error) {
      console.error('Failed to download report:', error)
      alert('Failed to download report. Please try again.')
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Reports</h1>
          <p className="text-muted-foreground mt-1">Generate and download security reports</p>
        </div>
        <button
          onClick={() => refetchReports()}
          className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Generate Report Section */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Generate Report</h2>
        
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
          <div>
            <label className="block text-sm font-medium mb-2">Select Scan</label>
            <select
              value={selectedScan}
              onChange={(e) => setSelectedScan(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="">Select a scan...</option>
              {scans?.filter(s => s.status === 'completed').map(scan => (
                <option key={scan.id} value={scan.id}>
                  {scan.name}
                </option>
              ))}
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Report Name</label>
            <input
              type="text"
              value={reportName}
              onChange={(e) => setReportName(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
              placeholder="My Report"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Format</label>
            <select
              value={selectedFormat}
              onChange={(e) => setSelectedFormat(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
            >
              {formats.filter(f => !f.disabled).map(format => (
                <option key={format.id} value={format.id}>{format.name}</option>
              ))}
            </select>
          </div>
          <div className="flex items-end">
            <button
              onClick={handleGenerateReport}
              disabled={generateReport.isPending || !selectedScan}
              className="w-full flex items-center justify-center gap-2 px-6 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
            >
              {generateReport.isPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                <>
                  <FileText className="h-4 w-4" />
                  Generate Report
                </>
              )}
            </button>
          </div>
        </div>

        {/* Format Selection Cards */}
        <div className="mb-6">
          <label className="block text-sm font-medium mb-2">Quick Format Selection</label>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {formats.map(format => (
              <button
                key={format.id}
                onClick={() => !format.disabled && setSelectedFormat(format.id)}
                disabled={format.disabled}
                className={cn(
                  "flex flex-col items-center gap-2 p-4 border rounded-xl transition-colors",
                  selectedFormat === format.id && "border-primary bg-primary/5",
                  format.disabled ? "opacity-50 cursor-not-allowed" : "hover:bg-muted"
                )}
              >
                <format.icon className={cn("h-8 w-8", format.color)} />
                <span className="text-sm font-medium">{format.name}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Generated Report Summary */}
        {generatedReport && (
          <div className="border-t pt-6 mt-6">
            <h3 className="font-semibold mb-4 text-green-500 flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Report Generated Successfully!
            </h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold">{generatedReport.format?.toUpperCase()}</p>
                <p className="text-sm text-muted-foreground">Format</p>
              </div>
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold">{generatedReport.id?.slice(0, 8)}</p>
                <p className="text-sm text-muted-foreground">Report ID</p>
              </div>
              <div className="p-4 bg-muted rounded-lg text-center">
                <p className="text-2xl font-bold">{formatDate(generatedReport.created_at || new Date().toISOString())}</p>
                <p className="text-sm text-muted-foreground">Generated</p>
              </div>
            </div>
            <div className="flex justify-end">
              <button
                onClick={() => setGeneratedReport(null)}
                className="px-4 py-2 border rounded-lg hover:bg-muted"
              >
                Generate Another
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Quick Download Section - Demo Report */}
      <div className="bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-xl p-6 border border-blue-500/20">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold flex items-center gap-2">
              <Download className="h-5 w-5 text-blue-500" />
              Rapport de démonstration disponible
            </h2>
            <p className="text-muted-foreground mt-1">
              Téléchargez le rapport de scan de sécurité généré pour maths-plus-plus.vercel.app
            </p>
          </div>
          <div className="flex gap-3">
            <a
              href={SAMPLE_REPORT.download_url}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-2 px-4 py-2 border border-blue-500 text-blue-500 rounded-lg hover:bg-blue-500/10"
            >
              <ExternalLink className="h-4 w-4" />
              Voir
            </a>
            <button
              onClick={() => {
                setIsDownloading(true)
                const link = document.createElement('a')
                link.href = SAMPLE_REPORT.download_url
                link.download = 'vulnscope_report.html'
                document.body.appendChild(link)
                link.click()
                document.body.removeChild(link)
                setTimeout(() => setIsDownloading(false), 1000)
              }}
              disabled={isDownloading}
              className="flex items-center gap-2 px-4 py-2 bg-blue-500 text-white rounded-lg hover:bg-blue-600 disabled:opacity-50"
            >
              {isDownloading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Téléchargement...
                </>
              ) : (
                <>
                  <Download className="h-4 w-4" />
                  Télécharger
                </>
              )}
            </button>
          </div>
        </div>
        <div className="mt-4 grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <span className="text-muted-foreground">Cible:</span>
            <p className="font-medium">maths-plus-plus.vercel.app</p>
          </div>
          <div>
            <span className="text-muted-foreground">Format:</span>
            <p className="font-medium">HTML</p>
          </div>
          <div>
            <span className="text-muted-foreground">Taille:</span>
            <p className="font-medium">12.9 KB</p>
          </div>
          <div>
            <span className="text-muted-foreground">Vulnérabilités:</span>
            <p className="font-medium">4 (2 Medium, 1 Low, 1 Info)</p>
          </div>
        </div>
      </div>

      {/* Report History */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Report History</h2>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : reports && reports.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="text-left py-3 px-4 font-medium">Name</th>
                  <th className="text-left py-3 px-4 font-medium">Format</th>
                  <th className="text-left py-3 px-4 font-medium">Scan</th>
                  <th className="text-left py-3 px-4 font-medium">Date</th>
                  <th className="text-left py-3 px-4 font-medium">Size</th>
                  <th className="text-left py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {reports.map((report: any) => {
                  const scan = scans?.find(s => s.id === report.scan_id)
                  return (
                    <tr key={report.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-3">
                          {getFormatIcon(report.format)}
                          <span className="font-medium">{report.name}</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className="px-2 py-1 bg-muted rounded-full text-xs">{report.format?.toUpperCase()}</span>
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {scan?.name || 'Unknown'}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {formatDate(report.created_at)}
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">{report.size || 'N/A'}</td>
                      <td className="py-3 px-4">
                        <button 
                          onClick={() => handleDownloadReport(report.id, report.format)}
                          className="flex items-center gap-2 px-3 py-1.5 text-sm bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
                        >
                          <Download className="h-4 w-4" />
                          Download
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <FileText className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No reports yet. Generate your first report above!</p>
          </div>
        )}
      </div>
    </div>
  )
}