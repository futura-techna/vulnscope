'use client'

import { useState, useEffect } from 'react'
import { 
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  LineChart, Line 
} from 'recharts'
import { 
  Scan, AlertTriangle, CheckCircle, Clock, 
  TrendingUp, TrendingDown, Activity, Loader2, RefreshCw, Target
} from 'lucide-react'
import { cn, formatDate, getSeverityColor } from '@/lib/utils'
import { useDashboardStats, useTargets, useScans, useFindings } from '@/lib/hooks/useApi'

interface StatCardProps {
  title: string
  value: number | string
  change?: number
  icon: any
  trend?: 'up' | 'down'
  loading?: boolean
}

function StatCard({ title, value, change, icon: Icon, trend, loading }: StatCardProps) {
  return (
    <div className="bg-card rounded-xl p-6 border">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground">{title}</p>
          {loading ? (
            <Loader2 className="h-6 w-6 animate-spin mt-2" />
          ) : (
            <p className="text-3xl font-bold mt-2">{value}</p>
          )}
          {change !== undefined && !loading && (
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
  const [isRefreshing, setIsRefreshing] = useState(false)

  // Fetch data using React Query hooks
  const { data: stats, isLoading: statsLoading, refetch: refetchStats } = useDashboardStats()
  const { data: targets, isLoading: targetsLoading } = useTargets()
  const { data: scans, isLoading: scansLoading } = useScans()
  const { data: findingsData, isLoading: findingsLoading } = useFindings({ limit: 100 })

  // Handle manual refresh
  const handleRefresh = async () => {
    setIsRefreshing(true)
    await refetchStats()
    setTimeout(() => setIsRefreshing(false), 500)
  }

  // Get unique target names for filtering
  const targetNames = targets?.map(t => t.name) || []
  const [selectedTargets, setSelectedTargets] = useState<string[]>([])

  // Update selected targets when targets load
  useEffect(() => {
    if (targetNames.length > 0 && selectedTargets.length === 0) {
      setSelectedTargets(targetNames.slice(0, 5))
    }
  }, [targetNames.length])

  // Filter findings
  const filteredFindings = findingsData?.findings.filter(f => {
    const matchesSeverity = selectedSeverities.includes(f.severity)
    const target = targets?.find(t => t.id === f.target_id)
    const matchesTarget = selectedTargets.length === 0 || selectedTargets.includes(target?.name || '')
    return matchesSeverity && matchesTarget
  }) || []

  // Prepare severity data for chart
  const severityData = [
    { name: 'Critical', count: stats?.critical_findings || 0, fill: '#FF4444' },
    { name: 'High', count: stats?.high_findings || 0, fill: '#FF8800' },
    { name: 'Medium', count: stats?.medium_findings || 0, fill: '#FFCC00' },
    { name: 'Low', count: stats?.low_findings || 0, fill: '#44AA44' },
    { name: 'Info', count: (stats?.total_findings || 0) - (stats?.critical_findings || 0) - (stats?.high_findings || 0) - (stats?.medium_findings || 0) - (stats?.low_findings || 0), fill: '#4488AA' },
  ]

  // Prepare trend data (mock for now, would come from backend)
  const trendData = [
    { week: 'Week 1', count: Math.max(10, (stats?.total_findings || 50) - 15 + Math.floor(Math.random() * 10)) },
    { week: 'Week 2', count: Math.max(10, (stats?.total_findings || 50) - 10 + Math.floor(Math.random() * 10)) },
    { week: 'Week 3', count: Math.max(10, (stats?.total_findings || 50) - 5 + Math.floor(Math.random() * 10)) },
    { week: 'Week 4', count: stats?.total_findings || 50 },
  ]

  // Get recent scans (last 5)
  const recentScans = scans?.slice(0, 5) || []

  const isLoading = statsLoading || targetsLoading || scansLoading || findingsLoading

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="text-muted-foreground mt-1">Monitor your security posture</p>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw className={cn("h-4 w-4", isRefreshing && "animate-spin")} />
          Refresh
        </button>
      </div>

      {/* Critical Alert */}
      {stats && stats.critical_findings > 0 && (
        <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-4">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-destructive mt-0.5" />
            <div>
              <h3 className="font-semibold text-destructive">CRITICAL ALERT</h3>
              <p className="text-sm mt-1">
                {stats.critical_findings} critical vulnerabilities detected! Immediate attention required.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard 
          title="Total Scans" 
          value={stats?.total_scans || 0} 
          change={stats?.scans_change} 
          icon={Scan}
          trend="up"
          loading={statsLoading}
        />
        <StatCard 
          title="Active Scans" 
          value={stats?.active_scans || 0} 
          icon={Activity}
          loading={statsLoading}
        />
        <StatCard 
          title="Critical Findings" 
          value={stats?.critical_findings || 0} 
          change={stats?.critical_change}
          icon={AlertTriangle}
          trend="down"
          loading={statsLoading}
        />
        <StatCard 
          title="High Findings" 
          value={stats?.high_findings || 0} 
          change={stats?.high_change}
          icon={CheckCircle}
          trend="up"
          loading={statsLoading}
        />
      </div>

      {/* Additional Stats Row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3">
            <Target className="h-5 w-5 text-muted-foreground" />
            <div>
              <p className="text-sm text-muted-foreground">Total Targets</p>
              <p className="text-2xl font-bold">{stats?.total_targets || 0}</p>
            </div>
          </div>
        </div>
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500" />
            <div>
              <p className="text-sm text-muted-foreground">Medium Findings</p>
              <p className="text-2xl font-bold">{stats?.medium_findings || 0}</p>
            </div>
          </div>
        </div>
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3">
            <CheckCircle className="h-5 w-5 text-blue-500" />
            <div>
              <p className="text-sm text-muted-foreground">Low Findings</p>
              <p className="text-2xl font-bold">{stats?.low_findings || 0}</p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Section */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Chart */}
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Findings by Severity</h2>
          {isLoading ? (
            <div className="flex items-center justify-center h-[300px]">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
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
          )}
        </div>

        {/* Trend Chart */}
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Vulnerability Trends</h2>
          {isLoading ? (
            <div className="flex items-center justify-center h-[300px]">
              <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            </div>
          ) : (
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
          )}
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
          {targetNames.length > 0 && (
            <div>
              <label className="text-sm text-muted-foreground block mb-2">Filter by Target</label>
              <div className="flex flex-wrap gap-2">
                {targetNames.slice(0, 5).map(target => (
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
          )}
        </div>
        <p className="text-sm text-muted-foreground mt-4">
          Showing {filteredFindings.length} findings
        </p>
      </div>

      {/* Recent Scans */}
      <div className="bg-card rounded-xl p-6 border">
        <h2 className="text-lg font-semibold mb-4">Recent Scans</h2>
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
          </div>
        ) : recentScans.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <Scan className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No scans yet. Create a target and start scanning!</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b">
                  <th className="text-left py-3 px-4 font-medium">Name</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Progress</th>
                  <th className="text-left py-3 px-4 font-medium">Findings</th>
                  <th className="text-left py-3 px-4 font-medium">Created</th>
                </tr>
              </thead>
              <tbody>
                {recentScans.map((scan) => {
                  const target = targets?.find(t => t.id === scan.target_id)
                  return (
                    <tr key={scan.id} className="border-b hover:bg-muted/50">
                      <td className="py-3 px-4">
                        <div>
                          <span className="font-medium">{scan.name}</span>
                          {target && (
                            <p className="text-xs text-muted-foreground">{target.name}</p>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={cn(
                          "px-2 py-1 rounded-full text-xs font-medium",
                          scan.status === 'completed' 
                            ? "bg-green-500/10 text-green-500"
                            : scan.status === 'running'
                            ? "bg-blue-500/10 text-blue-500"
                            : scan.status === 'failed'
                            ? "bg-red-500/10 text-red-500"
                            : "bg-yellow-500/10 text-yellow-500"
                        )}>
                          {scan.status}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 bg-muted rounded-full h-2">
                            <div
                              className="bg-primary h-2 rounded-full transition-all"
                              style={{ width: `${scan.progress || 0}%` }}
                            />
                          </div>
                          <span className="text-xs text-muted-foreground">{scan.progress || 0}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">{scan.findings_count || 0}</td>
                      <td className="py-3 px-4 text-muted-foreground">{formatDate(scan.created_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}