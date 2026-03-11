'use client'

import { useState } from 'react'
import { AlertTriangle, Filter, Download, Eye, Loader2, RefreshCw, X, CheckCircle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { cn, formatDate, getSeverityColor, getSeverityTextColor } from '@/lib/utils'
import { useFindings, useUpdateFinding, useTargets, useScans } from '@/lib/hooks/useApi'

export function Findings() {
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([])
  const [selectedTypes, setSelectedTypes] = useState<string[]>([])
  const [selectedStatus, setSelectedStatus] = useState('All')
  const [showCriticalOnly, setShowCriticalOnly] = useState(false)
  const [selectedFinding, setSelectedFinding] = useState<string | null>(null)

  // Fetch data using React Query hooks
  const { data: findingsData, isLoading: findingsLoading, refetch: refetchFindings } = useFindings({ limit: 100 })
  const { data: targets, isLoading: targetsLoading } = useTargets()
  const { data: scans, isLoading: scansLoading } = useScans()
  const updateFinding = useUpdateFinding()

  const isLoading = findingsLoading || targetsLoading || scansLoading

  // Get unique vulnerability types from findings
  const vulnTypes = [...new Set(findingsData?.findings.map(f => f.vuln_type) || [])]

  // Filter findings
  const filteredFindings = findingsData?.findings.filter(f => {
    if (showCriticalOnly && f.severity !== 'Critical') return false
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(f.severity)) return false
    if (selectedTypes.length > 0 && !selectedTypes.includes(f.vuln_type)) return false
    if (selectedStatus !== 'All' && f.status !== selectedStatus) return false
    return true
  }) || []

  const criticalFindings = findingsData?.findings.filter(f => f.severity === 'Critical') || []

  // Prepare chart data
  const severityTypeData = vulnTypes.map(type => ({
    type,
    count: findingsData?.findings.filter(f => f.vuln_type === type).length || 0
  })).sort((a, b) => b.count - a.count)

  const handleStatusUpdate = async (findingId: string, newStatus: string) => {
    try {
      await updateFinding.mutateAsync({
        id: findingId,
        data: { status: newStatus }
      })
    } catch (error) {
      console.error('Failed to update finding:', error)
    }
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Findings</h1>
          <p className="text-muted-foreground mt-1">View and manage vulnerabilities</p>
        </div>
        <button
          onClick={() => refetchFindings()}
          className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Critical Findings Alert */}
      {criticalFindings.length > 0 && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-destructive" />
              <div>
                <h3 className="font-semibold text-destructive">Critical Findings ({criticalFindings.length})</h3>
                <p className="text-sm text-muted-foreground">Immediate attention required</p>
              </div>
            </div>
            <button
              onClick={() => setShowCriticalOnly(!showCriticalOnly)}
              className="px-4 py-2 bg-destructive text-destructive-foreground rounded-lg hover:bg-destructive/90"
            >
              {showCriticalOnly ? 'Show All' : 'Show Critical Only'}
            </button>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="bg-card rounded-xl p-6 border">
        <div className="flex items-center gap-4 mb-4">
          <Filter className="h-5 w-5 text-muted-foreground" />
          <h2 className="font-semibold">Filters</h2>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-sm text-muted-foreground block mb-2">Severity</label>
            <div className="flex flex-wrap gap-2">
              {['Critical', 'High', 'Medium', 'Low', 'Info'].map(severity => (
                <button
                  key={severity}
                  onClick={() => {
                    setSelectedSeverities(prev => 
                      prev.includes(severity) 
                        ? prev.filter(s => s !== severity)
                        : [...prev, severity]
                    )
                  }}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                    selectedSeverities.includes(severity)
                      ? getSeverityColor(severity) + " text-white"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  )}
                >
                  {severity}
                </button>
              ))}
            </div>
          </div>
          {vulnTypes.length > 0 && (
            <div>
              <label className="text-sm text-muted-foreground block mb-2">Type</label>
              <div className="flex flex-wrap gap-2">
                {vulnTypes.slice(0, 6).map(type => (
                  <button
                    key={type}
                    onClick={() => {
                      setSelectedTypes(prev => 
                        prev.includes(type) 
                          ? prev.filter(t => t !== type)
                          : [...prev, type]
                      )
                    }}
                    className={cn(
                      "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                      selectedTypes.includes(type)
                        ? "bg-primary text-primary-foreground"
                        : "bg-muted text-muted-foreground hover:bg-muted/80"
                    )}
                  >
                    {type}
                  </button>
                ))}
              </div>
            </div>
          )}
          <div>
            <label className="text-sm text-muted-foreground block mb-2">Status</label>
            <select
              value={selectedStatus}
              onChange={(e) => setSelectedStatus(e.target.value)}
              className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
            >
              <option value="All">All</option>
              <option value="Open">Open</option>
              <option value="In Progress">In Progress</option>
              <option value="Resolved">Resolved</option>
              <option value="False Positive">False Positive</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Count */}
      <div className="text-sm text-muted-foreground">
        Showing {filteredFindings.length} of {findingsData?.total || 0} findings
      </div>

      {/* Findings Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : filteredFindings.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <CheckCircle className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No findings match your filters.</p>
            {(selectedSeverities.length > 0 || selectedTypes.length > 0 || selectedStatus !== 'All') && (
              <button
                onClick={() => {
                  setSelectedSeverities([])
                  setSelectedTypes([])
                  setSelectedStatus('All')
                  setShowCriticalOnly(false)
                }}
                className="mt-2 text-primary hover:underline"
              >
                Clear filters
              </button>
            )}
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="text-left py-3 px-4 font-medium">ID</th>
                  <th className="text-left py-3 px-4 font-medium">Title</th>
                  <th className="text-left py-3 px-4 font-medium">Severity</th>
                  <th className="text-left py-3 px-4 font-medium">Type</th>
                  <th className="text-left py-3 px-4 font-medium">Target</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredFindings.map((finding) => {
                  const target = targets?.find(t => t.id === finding.target_id)
                  return (
                    <tr key={finding.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-4 font-mono text-sm">{finding.id.slice(0, 8)}</td>
                      <td className="py-3 px-4 max-w-md">
                        <div>
                          <span className="truncate block">{finding.title}</span>
                          {finding.url && (
                            <p className="text-xs text-muted-foreground truncate">{finding.url}</p>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          getSeverityColor(finding.severity) + " text-white"
                        )}>
                          {finding.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 text-muted-foreground">{finding.vuln_type}</td>
                      <td className="py-3 px-4 text-muted-foreground">
                        {target?.name || 'Unknown'}
                      </td>
                      <td className="py-3 px-4">
                        <select
                          value={finding.status}
                          onChange={(e) => handleStatusUpdate(finding.id, e.target.value)}
                          disabled={updateFinding.isPending}
                          className={cn(
                            "px-2 py-1 rounded-full text-xs font-medium border-0 cursor-pointer",
                            finding.status === 'Open' && "bg-red-500/10 text-red-500",
                            finding.status === 'In Progress' && "bg-blue-500/10 text-blue-500",
                            finding.status === 'Resolved' && "bg-green-500/10 text-green-500",
                            finding.status === 'False Positive' && "bg-gray-500/10 text-gray-500"
                          )}
                        >
                          <option value="Open">Open</option>
                          <option value="In Progress">In Progress</option>
                          <option value="Resolved">Resolved</option>
                          <option value="False Positive">False Positive</option>
                        </select>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <button 
                            onClick={() => setSelectedFinding(finding.id === selectedFinding ? null : finding.id)}
                            className="p-2 hover:bg-muted rounded-lg" 
                            title="View Details"
                          >
                            <Eye className="h-4 w-4 text-muted-foreground" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Finding Detail Modal */}
      {selectedFinding && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4">
          <div className="bg-card rounded-xl border max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            {(() => {
              const finding = findingsData?.findings.find(f => f.id === selectedFinding)
              const target = targets?.find(t => t.id === finding?.target_id)
              const scan = scans?.find(s => s.id === finding?.scan_id)
              
              if (!finding) return null
              
              return (
                <div className="p-6">
                  <div className="flex items-start justify-between mb-4">
                    <div>
                      <h2 className="text-xl font-bold">{finding.title}</h2>
                      <p className="text-sm text-muted-foreground mt-1">{finding.vuln_type}</p>
                    </div>
                    <button
                      onClick={() => setSelectedFinding(null)}
                      className="p-2 hover:bg-muted rounded-lg"
                    >
                      <X className="h-5 w-5" />
                    </button>
                  </div>
                  
                  <div className="space-y-4">
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-muted-foreground">Severity</p>
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          getSeverityColor(finding.severity) + " text-white"
                        )}>
                          {finding.severity}
                        </span>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Status</p>
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          finding.status === 'Open' && "bg-red-500/10 text-red-500",
                          finding.status === 'In Progress' && "bg-blue-500/10 text-blue-500",
                          finding.status === 'Resolved' && "bg-green-500/10 text-green-500"
                        )}>
                          {finding.status}
                        </span>
                      </div>
                    </div>
                    
                    {finding.url && (
                      <div>
                        <p className="text-sm text-muted-foreground">URL</p>
                        <p className="font-mono text-sm break-all">{finding.url}</p>
                      </div>
                    )}
                    
                    {finding.method && (
                      <div>
                        <p className="text-sm text-muted-foreground">Method</p>
                        <span className="px-2 py-1 bg-muted rounded text-sm font-mono">{finding.method}</span>
                      </div>
                    )}
                    
                    {finding.parameter && (
                      <div>
                        <p className="text-sm text-muted-foreground">Parameter</p>
                        <p className="font-mono text-sm">{finding.parameter}</p>
                      </div>
                    )}
                    
                    {finding.payload && (
                      <div>
                        <p className="text-sm text-muted-foreground">Payload</p>
                        <code className="block p-2 bg-muted rounded text-sm font-mono break-all">{finding.payload}</code>
                      </div>
                    )}
                    
                    {finding.evidence && (
                      <div>
                        <p className="text-sm text-muted-foreground">Evidence</p>
                        <code className="block p-2 bg-muted rounded text-sm font-mono break-all">{finding.evidence}</code>
                      </div>
                    )}
                    
                    <div className="grid grid-cols-2 gap-4 pt-4 border-t">
                      <div>
                        <p className="text-sm text-muted-foreground">Target</p>
                        <p>{target?.name || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Scan</p>
                        <p>{scan?.name || 'Unknown'}</p>
                      </div>
                      <div>
                        <p className="text-sm text-muted-foreground">Found</p>
                        <p>{formatDate(finding.created_at)}</p>
                      </div>
                      {finding.cvss_score && (
                        <div>
                          <p className="text-sm text-muted-foreground">CVSS Score</p>
                          <p>{finding.cvss_score}</p>
                        </div>
                      )}
                    </div>
                  </div>
                  
                  <div className="flex justify-end gap-2 mt-6 pt-4 border-t">
                    <button
                      onClick={() => setSelectedFinding(null)}
                      className="px-4 py-2 border rounded-lg hover:bg-muted"
                    >
                      Close
                    </button>
                    <button
                      onClick={() => handleStatusUpdate(finding.id, 'Resolved')}
                      disabled={updateFinding.isPending}
                      className="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 disabled:opacity-50"
                    >
                      Mark Resolved
                    </button>
                  </div>
                </div>
              )
            })()}
          </div>
        </div>
      )}

      {/* Findings by Type Chart */}
      {severityTypeData.length > 0 && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Findings by Type</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityTypeData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="type" className="text-xs" />
              <YAxis className="text-xs" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--card))', 
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px'
                }}
              />
              <Bar dataKey="count" fill="hsl(var(--primary))" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}