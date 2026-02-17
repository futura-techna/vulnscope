'use client'

import { useState } from 'react'
import { Play, Plus, Clock, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

const scansData = [
  { Name: 'Full Scan - Production', Target: 'app.example.com', Status: 'Completed', Findings: 23, Date: '2024-01-15' },
  { Name: 'Quick Scan - Dev', Target: 'dev.example.com', Status: 'Completed', Findings: 5, Date: '2024-01-14' },
  { Name: 'API Security Scan', Target: 'api.example.com', Status: 'Running', Findings: 8, Date: '2024-01-14' },
  { Name: 'Auth Test', Target: 'auth.example.com', Status: 'Completed', Findings: 12, Date: '2024-01-13' },
]

export function Scans() {
  const [showForm, setShowForm] = useState(false)
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [formData, setFormData] = useState({
    name: '',
    target: '',
    type: 'full',
    description: '',
    enableCrawler: true,
    enableDast: true,
    enableFuzzer: false,
    enableOpenapi: false,
    maxConcurrent: 10,
    timeout: 30,
    recursiveDepth: 3,
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Start scan simulation
    setIsScanning(true)
    setScanProgress(0)
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev >= 100) {
          clearInterval(interval)
          setIsScanning(false)
          return 100
        }
        return prev + 10
      })
    }, 500)
  }

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'Completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'Running':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      case 'Failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scans</h1>
          <p className="text-muted-foreground mt-1">Create and manage security scans</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" />
          New Scan
        </button>
      </div>

      {/* Create Scan Form */}
      {showForm && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Create New Scan</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Scan Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="New Security Scan"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Target URL</label>
                <input
                  type="url"
                  value={formData.target}
                  onChange={(e) => setFormData({ ...formData, target: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="https://app.example.com"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Scan Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option value="full">Full Scan</option>
                  <option value="quick">Quick Scan</option>
                  <option value="api">API Security Scan</option>
                  <option value="auth">Auth Test</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="Security vulnerability scan"
                />
              </div>
            </div>

            {/* Scan Options */}
            <div className="border-t pt-4 mt-4">
              <h3 className="font-medium mb-4">Scan Options</h3>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enableCrawler}
                    onChange={(e) => setFormData({ ...formData, enableCrawler: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm">Enable Crawler</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enableDast}
                    onChange={(e) => setFormData({ ...formData, enableDast: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm">Enable DAST</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enableFuzzer}
                    onChange={(e) => setFormData({ ...formData, enableFuzzer: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm">Enable Fuzzer</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={formData.enableOpenapi}
                    onChange={(e) => setFormData({ ...formData, enableOpenapi: e.target.checked })}
                    className="rounded border-gray-300"
                  />
                  <span className="text-sm">Import OpenAPI</span>
                </label>
              </div>
            </div>

            {/* Advanced Options */}
            <div className="border-t pt-4 mt-4">
              <h3 className="font-medium mb-4">Advanced Options</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Max Concurrent Requests</label>
                  <input
                    type="number"
                    value={formData.maxConcurrent}
                    onChange={(e) => setFormData({ ...formData, maxConcurrent: parseInt(e.target.value) })}
                    className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                    min={1}
                    max={100}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Request Timeout (s)</label>
                  <input
                    type="number"
                    value={formData.timeout}
                    onChange={(e) => setFormData({ ...formData, timeout: parseInt(e.target.value) })}
                    className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                    min={5}
                    max={120}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Recursive Scan Depth</label>
                  <input
                    type="number"
                    value={formData.recursiveDepth}
                    onChange={(e) => setFormData({ ...formData, recursiveDepth: parseInt(e.target.value) })}
                    className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                    min={1}
                    max={5}
                  />
                </div>
              </div>
            </div>

            {/* Progress Bar */}
            {isScanning && (
              <div className="border-t pt-4 mt-4">
                <div className="flex items-center justify-between mb-2">
                  <span className="text-sm font-medium">Scan Progress</span>
                  <span className="text-sm text-muted-foreground">{scanProgress}%</span>
                </div>
                <div className="w-full bg-muted rounded-full h-2">
                  <div
                    className="bg-primary h-2 rounded-full transition-all duration-300"
                    style={{ width: `${scanProgress}%` }}
                  />
                </div>
              </div>
            )}

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="px-4 py-2 border rounded-lg hover:bg-muted"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={isScanning}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
              >
                <Play className="h-4 w-4" />
                {isScanning ? 'Scanning...' : 'Start Scan'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Scan Results (shown after scan) */}
      {scanProgress === 100 && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Scan Results</h2>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-muted rounded-lg text-center">
              <p className="text-2xl font-bold">150</p>
              <p className="text-sm text-muted-foreground">Endpoints Found</p>
            </div>
            <div className="p-4 bg-muted rounded-lg text-center">
              <p className="text-2xl font-bold">12</p>
              <p className="text-sm text-muted-foreground">Vulnerabilities</p>
            </div>
            <div className="p-4 bg-muted rounded-lg text-center">
              <p className="text-2xl font-bold text-red-500">3</p>
              <p className="text-sm text-muted-foreground">Critical</p>
            </div>
            <div className="p-4 bg-muted rounded-lg text-center">
              <p className="text-2xl font-bold text-orange-500">5</p>
              <p className="text-sm text-muted-foreground">High</p>
            </div>
          </div>
        </div>
      )}

      {/* Scan History */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left py-3 px-4 font-medium">Name</th>
                <th className="text-left py-3 px-4 font-medium">Target</th>
                <th className="text-left py-3 px-4 font-medium">Status</th>
                <th className="text-left py-3 px-4 font-medium">Findings</th>
                <th className="text-left py-3 px-4 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {scansData.map((scan, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4 font-medium">{scan.Name}</td>
                  <td className="py-3 px-4 text-muted-foreground">{scan.Target}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      {getStatusIcon(scan.Status)}
                      <span className={cn(
                        "text-sm",
                        scan.Status === 'Completed' && "text-green-500",
                        scan.Status === 'Running' && "text-blue-500",
                        scan.Status === 'Failed' && "text-red-500"
                      )}>
                        {scan.Status}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4">{scan.Findings}</td>
                  <td className="py-3 px-4 text-muted-foreground">{formatDate(scan.Date)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
