'use client'

import { useState } from 'react'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line 
} from 'recharts'
import { 
  Scan, AlertTriangle, CheckCircle, Clock, 
  TrendingUp, TrendingDown, Activity 
} from 'lucide-react'
import { cn, formatDate, getSeverityColor } from '@/lib/utils'

// Sample data matching the Streamlit app
const stats = {
  totalScans: 150,
  scansChange: 12,
  activeScans: 3,
  criticalFindings: 2,
  criticalChange: -3,
  highFindings: 45,
  highChange: 5,
}

const findingsData = [
  { ID: 'VULN-001', Title: 'SQL Injection in /api/users', Severity: 'Critical', Type: 'SQL Injection', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-002', Title: 'XSS in search parameter', Severity: 'High', Type: 'XSS', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-003', Title: 'SSRF in URL parameter', Severity: 'High', Type: 'SSRF', Target: 'api.example.com', Status: 'In Progress' },
  { ID: 'VULN-004', Title: 'IDOR in /user/profile', Severity: 'Medium', Type: 'IDOR', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-005', Title: 'CSRF missing token', Severity: 'Medium', Type: 'CSRF', Target: 'app.example.com', Status: 'Open' },
  { ID: 'VULN-006', Title: 'XXE in XML parser', Severity: 'Critical', Type: 'XXE', Target: 'api.example.com', Status: 'Open' },
]

const severityData = [
  { name: 'Critical', count: 2, fill: '#FF4444' },
  { name: 'High', count: 45, fill: '#FF8800' },
  { name: 'Medium', count: 30, fill: '#FFCC00' },
  { name: 'Low', count: 25, fill: '#44AA44' },
  { name: 'Info', count: 15, fill: '#4488AA' },
]

const trendData = [
  { week: 'Week 1', count: 15 },
  { week: 'Week 2', count: 23 },
  { week: 'Week 3', count: 18 },
  { week: 'Week 4', count: 25 },
]

const recentScans = [
  { Name: 'Full Scan - Production', Target: 'app.example.com', Status: 'Completed', Findings: 23, Date: '2024-01-15' },
  { Name: 'Quick Scan - Dev', Target: 'dev.example.com', Status: 'Completed', Findings: 5, Date: '2024-01-14' },
  { Name: 'API Security Scan', Target: 'api.example.com', Status: 'Running', Findings: 8, Date: '2024-01-14' },
  { Name: 'Auth Test', Target: 'auth.example.com', Status: 'Completed', Findings: 12, Date: '2024-01-13' },
]

interface StatCardProps {
  title: string
  value: number | string
  change?: number
  icon: any
  trend?: 'up' | 'down'
}

function StatCard({ title, value, change, icon: Icon, trend }: StatCardProps) {
  return (
    <div className="bg-card rounded-xl p-6 border">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          <p className="text-3xl font-bold mt-2">{value}</p>
          {change !== undefined && (
            <div className={cn(
              "flex items-center gap-1 mt-2 text-sm",
              change >= 0 ? "text-green-500" : "text-red-500"
            )}>
              {trend === 'up' || (change > 0) ? (
                <TrendingUp className="h-4 w-4" />
              ) : (
                <TrendingDown className="h-4 w-4" />
              )}
              <span>{Math.abs(change)}</span>
            </div>
          )}
        </div>
        <div className="p-3 bg-primary/10 rounded-lg">
          <Icon className="h-6 w-6 text-primary" />
        </div>
      </div>
    </div>
  )
}

export function Dashboard() {
  const [selectedSeverities, setSelectedSeverities] = useState<string[]>(['Critical', 'High', 'Medium', 'Low'])
  const [selectedTargets, setSelectedTargets] = useState<string[]>(['app.example.com', 'api.example.com'])

  const filteredFindings = findingsData.filter(f => 
    selectedSeverities.includes(f.Severity) && selectedTargets.includes(f.Target)
  )

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-3xl font-bold">Dashboard</h1>
        <p className="text-muted-foreground mt-1">Monitor your security posture</p>
      </div>

      {/* Critical Alert */}
      {stats.criticalFindings > 0 && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive mt-0.5" />
            <div>
              <h3 className="font-semibold text-destructive">CRITICAL ALERT</h3>
              <p className="text-sm mt-1">
                {stats.criticalFindings} critical vulnerabilities detected! Immediate attention required.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total Scans" 
          value={stats.totalScans} 
          change={stats.scansChange} 
          icon={Scan}
          trend="up"
        />
        <StatCard 
          title="Active Scans" 
          value={stats.activeScans} 
          icon={Activity}
        />
        <StatCard 
          title="Critical Findings" 
          value={stats.criticalFindings} 
          change={stats.criticalChange}
          icon={AlertTriangle}
          trend="down"
        />
        <StatCard 
          title="High Findings" 
          value={stats.highFindings} 
          change={stats.highChange}
          icon={CheckCircle}
          trend="up"
        />
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Chart */}
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={severityData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="name" className="text-xs" />
              <YAxis className="text-xs" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--card))', 
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px'
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Trend Chart */}
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Vulnerability Trends</h2>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={trendData}>
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis dataKey="week" className="text-xs" />
              <YAxis className="text-xs" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--card))', 
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px'
                }}
              />
              <Line 
                type="monotone" 
                dataKey="count" 
                stroke="hsl(var(--primary))" 
                strokeWidth={2}
                dot={{ fill: 'hsl(var(--primary))' }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Filters */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Interactive Analysis</h2>
        <div className="flex flex-wrap gap-4">
          <div>
            <label className="text-sm text-muted-foreground block mb-2">Filter by Severity</label>
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
            <label className="text-sm text-muted-foreground block mb-2">Filter by Target</label>
            <div className="flex flex-wrap gap-2">
              {['app.example.com', 'api.example.com'].map(target => (
                <button
                  key={target}
                  onClick={() => {
                    setSelectedTargets(prev => 
                      prev.includes(target) 
                        ? prev.filter(t => t !== target)
                        : [...prev, target]
                    )
                  }}
                  className={cn(
                    "px-3 py-1.5 rounded-lg text-sm font-medium transition-colors",
                    selectedTargets.includes(target)
                      ? "bg-primary text-primary-foreground"
                      : "bg-muted text-muted-foreground hover:bg-muted/80"
                  )}
                >
                  {target}
                </button>
              ))}
            </div>
          </div>
        </div>
        <p className="text-sm text-muted-foreground mt-4">
          Showing {filteredFindings.length} findings
        </p>
      </div>

      {/* Recent Scans */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b">
                <th className="text-left py-3 px-4 font-medium">Name</th>
                <th className="text-left py-3 px-4 font-medium">Target</th>
                <th className="text-left py-3 px-4 font-medium">Status</th>
                <th className="text-left py-3 px-4 font-medium">Findings</th>
                <th className="text-left py-3 px-4 font-medium">Date</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.map((scan, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4">{scan.Name}</td>
                  <td className="py-3 px-4 text-muted-foreground">{scan.Target}</td>
                  <td className="py-3 px-4">
                    <span className={cn(
                      "px-2 py-1 rounded-full text-xs font-medium",
                      scan.Status === 'Completed' 
                        ? "bg-green-500/10 text-green-500"
                        : "bg-blue-500/10 text-blue-500"
                    )}>
                      {scan.Status}
                    </span>
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
