'use client'

import { useState } from 'react'
import { AlertTriangle, Filter, Download, Eye } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { cn, formatDate, getSeverityColor, getSeverityTextColor } from '@/lib/utils'

const findingsData = [
  { ID: 'VULN-001', Title: 'SQL Injection in /api/users', Severity: 'Critical', Type: 'SQL Injection', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-002', Title: 'XSS in search parameter', Severity: 'High', Type: 'XSS', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-003', Title: 'SSRF in URL parameter', Severity: 'High', Type: 'SSRF', Target: 'api.example.com', Status: 'In Progress' },
  { ID: 'VULN-004', Title: 'IDOR in /user/profile', Severity: 'Medium', Type: 'IDOR', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-005', Title: 'CSRF missing token', Severity: 'Medium', Type: 'CSRF', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-006', Title: 'XXE in XML parser', Severity: 'Critical', Type: 'XXE', Target: 'api.example.com', Status: 'Open' },
]

const severityTypeData = [
  { type: 'SQL Injection', count: 2 },
  { type: 'XSS', count: 5 },
  { type: 'SSRF', count: 3 },
  { type: 'IDOR', count: 4 },
  { type: 'CSRF', count: 2 },
]

export function Findings() {
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>([])
  const [selectedTypes, setSelectedTypes] = useState<string[]>([])
  const [selectedStatus, setSelectedStatus] = useState('All')
  const [showCriticalOnly, setShowCriticalOnly] = useState(false)

  const criticalFindings = findingsData.filter(f => f.Severity === 'Critical')

  const filteredFindings = findingsData.filter(f => {
    if (showCriticalOnly && f.Severity !== 'Critical') return false
    if (selectedSeverities.length > 0 && !selectedSeverities.includes(f.Severity)) return false
    if (selectedTypes.length > 0 && !selectedTypes.includes(f.Type)) return false
    if (selectedStatus !== 'All' && f.Status !== selectedStatus) return false
    return true
  })

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Findings</h1>
          <p className="text-muted-foreground mt-1">View and manage vulnerabilities</p>
        </div>
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
              {['Critical', 'High', 'Medium', 'Low'].map(severity => (
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
          <div>
            <label className="text-sm text-muted-foreground block mb-2">Type</label>
            <div className="flex flex-wrap gap-2">
              {['SQL Injection', 'XSS', 'SSRF', 'IDOR', 'CSRF'].map(type => (
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
        Showing {filteredFindings.length} findings
      </div>

      {/* Findings Table */}
      <div className="bg-card rounded-xl border overflow-hidden">
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
              {filteredFindings.map((finding, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4 font-mono text-sm">{finding.ID}</td>
                  <td className="py-3 px-4 max-w-md truncate">{finding.Title}</td>
                  <td className="py-3 px-4">
                    <span className={cn(
                      "px-2 py-1 rounded-full text-xs font-medium",
                      getSeverityColor(finding.Severity) + " text-white"
                    )}>
                      {finding.Severity}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">{finding.Type}</td>
                  <td className="py-3 px-4 text-muted-foreground">{finding.Target}</td>
                  <td className="py-3 px-4">
                    <span className={cn(
                      "px-2 py-1 rounded-full text-xs font-medium",
                      finding.Status === 'Open' && "bg-red-500/10 text-red-500",
                      finding.Status === 'In Progress' && "bg-blue-500/10 text-blue-500",
                      finding.Status === 'Resolved' && "bg-green-500/10 text-green-500"
                    )}>
                      {finding.Status}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <button className="p-2 hover:bg-muted rounded-lg" title="View Details">
                        <Eye className="h-4 w-4 text-muted-foreground" />
                      </button>
                      <button className="p-2 hover:bg-muted rounded-lg" title="Export">
                        <Download className="h-4 w-4 text-muted-foreground" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Findings by Type Chart */}
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
    </div>
  )
}
