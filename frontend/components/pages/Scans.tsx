'use client'

import { useState } from 'react'
import { Play, Plus, Clock, CheckCircle, AlertCircle, Loader2, X, RefreshCw, Target } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useScans, useCreateScan, useCancelScan, useTargets } from '@/lib/hooks/useApi'
import { ScanCreate } from '@/lib/api'

export function Scans() {
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    target_id: '',
    scan_type: 'full',
    description: '',
    enableCrawler: true,
    enableDast: true,
    enableFuzzer: false,
    enableOpenapi: false,
    maxConcurrent: 10,
    timeout: 30,
    recursiveDepth: 3,
  })

  // Fetch data using React Query hooks
  const { data: scans, isLoading: scansLoading, refetch: refetchScans } = useScans()
  const { data: targets, isLoading: targetsLoading } = useTargets()
  const createScan = useCreateScan()
  const cancelScan = useCancelScan()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (!formData.target_id) {
      alert('Please select a target')
      return
    }

    const scanData: ScanCreate = {
      target_id: formData.target_id,
      name: formData.name,
      description: formData.description,
      scan_type: formData.scan_type,
      enable_crawler: formData.enableCrawler,
      enable_dast: formData.enableDast,
      enable_fuzzer: formData.enableFuzzer,
      enable_openapi_import: formData.enableOpenapi,
    }

    try {
      await createScan.mutateAsync(scanData)
      setShowForm(false)
      // Reset form
      setFormData({
        name: '',
        target_id: '',
        scan_type: 'full',
        description: '',
        enableCrawler: true,
        enableDast: true,
        enableFuzzer: false,
        enableOpenapi: false,
        maxConcurrent: 10,
        timeout: 30,
        recursiveDepth: 3,
      })
    } catch (error) {
      console.error('Failed to create scan:', error)
      alert('Failed to create scan. Please try again.')
    }
  }

  const handleCancelScan = async (scanId: string) => {
    if (confirm('Are you sure you want to cancel this scan?')) {
      try {
        await cancelScan.mutateAsync(scanId)
      } catch (error) {
        console.error('Failed to cancel scan:', error)
      }
    }
  }

  const getStatusIcon = (status: string) => {
    switch (status?.toLowerCase()) {
      case 'completed':
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case 'running':
        return <Loader2 className="h-4 w-4 text-blue-500 animate-spin" />
      case 'pending':
        return <Clock className="h-4 w-4 text-yellow-500" />
      case 'failed':
        return <AlertCircle className="h-4 w-4 text-red-500" />
      case 'cancelled':
        return <X className="h-4 w-4 text-gray-500" />
      default:
        return <Clock className="h-4 w-4 text-muted-foreground" />
    }
  }

  const isLoading = scansLoading || targetsLoading

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Scans</h1>
          <p className="text-muted-foreground mt-1">Create and manage security scans</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetchScans()}
            className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button
            onClick={() => setShowForm(!showForm)}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            New Scan
          </button>
        </div>
      </div>

      {/* Create Scan Form */}
      {showForm && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Create New Scan</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Scan Name *</label>
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
                <label className="block text-sm font-medium mb-2">Target *</label>
                <select
                  value={formData.target_id}
                  onChange={(e) => setFormData({ ...formData, target_id: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  required
                >
                  <option value="">Select a target...</option>
                  {targets?.map(target => (
                    <option key={target.id} value={target.id}>
                      {target.name} ({target.url})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Scan Type</label>
                <select
                  value={formData.scan_type}
                  onChange={(e) => setFormData({ ...formData, scan_type: e.target.value })}
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
                disabled={createScan.isPending}
                className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
              >
                {createScan.isPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Starting...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Start Scan
                  </>
                )}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Active Scans Summary */}
      {scans && scans.some(s => s.status === 'running' || s.status === 'pending') && (
        <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4">
          <div className="flex items-center gap-3">
            <Loader2 className="h-5 w-5 text-blue-500 animate-spin" />
            <div>
              <h3 className="font-semibold text-blue-500">Active Scans</h3>
              <p className="text-sm">
                {scans.filter(s => s.status === 'running' || s.status === 'pending').length} scan(s) in progress
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Scan History */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Scan History</h2>
        </div>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : scans && scans.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="text-left py-3 px-4 font-medium">Name</th>
                  <th className="text-left py-3 px-4 font-medium">Target</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Progress</th>
                  <th className="text-left py-3 px-4 font-medium">Findings</th>
                  <th className="text-left py-3 px-4 font-medium">Created</th>
                  <th className="text-left py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {scans.map((scan) => {
                  const target = targets?.find(t => t.id === scan.target_id)
                  return (
                    <tr key={scan.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-4 font-medium">{scan.name}</td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {target ? (
                          <div>
                            <span>{target.name}</span>
                            <p className="text-xs">{target.url}</p>
                          </div>
                        ) : (
                          'Unknown'
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          {getStatusIcon(scan.status)}
                          <span className={cn(
                            "text-sm capitalize",
                            scan.status === 'completed' && "text-green-500",
                            scan.status === 'running' && "text-blue-500",
                            scan.status === 'pending' && "text-yellow-500",
                            scan.status === 'failed' && "text-red-500",
                            scan.status === 'cancelled' && "text-gray-500"
                          )}>
                            {scan.status}
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-20 bg-muted rounded-full h-2">
                            <div
                              className={cn(
                                "h-2 rounded-full transition-all",
                                scan.status === 'completed' ? "bg-green-500" :
                                scan.status === 'failed' ? "bg-red-500" :
                                "bg-primary"
                              )}
                              style={{ width: `${scan.progress || 0}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground w-10">
                            {scan.progress || 0}%
                          </span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={cn(
                          "font-medium",
                          (scan.findings_count || 0) > 0 ? "text-red-500" : "text-green-500"
                        )}>
                          {scan.findings_count || 0}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {formatDate(scan.created_at)}
                      </td>
                      <td className="py-3 px-4">
                        {(scan.status === 'running' || scan.status === 'pending') && (
                          <button
                            onClick={() => handleCancelScan(scan.id)}
                            className="px-3 py-1 text-sm border rounded-lg hover:bg-muted text-red-500 border-red-200"
                          >
                            Cancel
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <Target className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No scans yet. Create a target and start a scan!</p>
          </div>
        )}
      </div>
    </div>
  )
}