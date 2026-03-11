'use client'

import { useState, useEffect } from 'react'
import { FileCheck, CheckCircle, AlertTriangle, Loader2, RefreshCw } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { cn } from '@/lib/utils'
import api from '@/lib/api'

interface ComplianceStandard {
  name: string
  score: number
  status: 'pass' | 'warning' | 'fail'
  requirements_met: number
  requirements_total: number
}

interface ComplianceCategory {
  name: string
  score: number
}

export function Compliance() {
  const [standards, setStandards] = useState<ComplianceStandard[]>([])
  const [categories, setCategories] = useState<ComplianceCategory[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchCompliance = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const [standardsRes, categoriesRes] = await Promise.all([
        api.client.get('/compliance/standards'),
        api.client.get('/compliance/categories')
      ])
      setStandards(standardsRes.data.standards || [])
      setCategories(categoriesRes.data.categories || [])
    } catch (err) {
      console.error('Failed to fetch compliance data:', err)
      setError('Failed to load compliance data')
    } finally {
      setIsLoading(false)
    }
  }

  useEffect(() => {
    fetchCompliance()
  }, [])

  const getScoreColor = (score: number) => {
    if (score >= 90) return '#22c55e' // green
    if (score >= 70) return '#eab308' // yellow
    return '#ef4444' // red
  }

  const getStatusIcon = (status: string) => {
    if (status === 'pass') {
      return <CheckCircle className="h-5 w-5 text-green-500" />
    }
    return <AlertTriangle className="h-5 w-5 text-yellow-500" />
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-6">
        <h1 className="text-3xl font-bold">Compliance</h1>
        <div className="bg-destructive/10 border border-destructive/20 rounded-xl p-6 text-center">
          <AlertTriangle className="h-12 w-12 mx-auto mb-4 text-destructive" />
          <p className="text-destructive">{error}</p>
          <button
            onClick={fetchCompliance}
            className="mt-4 px-4 py-2 border rounded-lg hover:bg-muted"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Compliance</h1>
          <p className="text-muted-foreground mt-1">Monitor compliance with security standards</p>
        </div>
        <button
          onClick={fetchCompliance}
          className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </button>
      </div>

      {/* Standards Overview */}
      {standards.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
          {standards.map((standard, i) => (
            <div key={i} className="bg-card rounded-xl p-6 border">
              <div className="flex items-center justify-between mb-4">
                <span className="font-medium">{standard.name}</span>
                {getStatusIcon(standard.status)}
              </div>
              <div className="text-3xl font-bold" style={{ color: getScoreColor(standard.score) }}>
                {Math.round(standard.score)}%
              </div>
              <div className="w-full bg-muted rounded-full h-2 mt-4">
                <div
                  className="h-2 rounded-full transition-all"
                  style={{ 
                    width: `${standard.score}%`,
                    backgroundColor: getScoreColor(standard.score)
                  }}
                />
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Compliance by Category */}
      {categories.length > 0 && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Compliance by Category</h2>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={categories} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis type="number" domain={[0, 100]} className="text-xs" />
              <YAxis type="category" dataKey="name" width={150} className="text-xs" />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--card))', 
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '8px'
                }}
                formatter={(value: number) => [`${Math.round(value)}%`, 'Score']}
              />
              <Bar dataKey="score" radius={[0, 4, 4, 0]}>
                {categories.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={getScoreColor(entry.score)} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Detailed Standards */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Compliance Details</h2>
        </div>
        {standards.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="text-left py-3 px-4 font-medium">Standard</th>
                  <th className="text-left py-3 px-4 font-medium">Score</th>
                  <th className="text-left py-3 px-4 font-medium">Status</th>
                  <th className="text-left py-3 px-4 font-medium">Requirements Met</th>
                  <th className="text-left py-3 px-4 font-medium">Progress</th>
                </tr>
              </thead>
              <tbody>
                {standards.map((item, i) => (
                  <tr key={i} className="border-b hover:bg-muted/50">
                    <td className="py-3 px-4 font-medium">{item.name}</td>
                    <td className="py-3 px-4">
                      <span 
                        className="font-bold"
                        style={{ color: getScoreColor(item.score) }}
                      >
                        {Math.round(item.score)}%
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      {getStatusIcon(item.status)}
                    </td>
                    <td className="py-3 px-4">
                      {item.requirements_met} / {item.requirements_total}
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-24 bg-muted rounded-full h-2">
                          <div
                            className="h-2 rounded-full transition-all"
                            style={{ 
                              width: `${(item.requirements_met / item.requirements_total) * 100}%`,
                              backgroundColor: getScoreColor(item.score)
                            }}
                          />
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {Math.round((item.requirements_met / item.requirements_total) * 100)}%
                        </span>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <FileCheck className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No compliance data available.</p>
            <p className="text-sm mt-2">Run some scans to generate compliance reports.</p>
          </div>
        )}
      </div>

      {/* Compliance Recommendations */}
      {standards.some(s => s.status === 'warning') && (
        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-6">
          <div className="flex items-start gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-500 mt-0.5" />
            <div>
              <h3 className="font-semibold text-yellow-500">Recommendations</h3>
              <ul className="mt-2 text-sm space-y-2">
                {standards.filter(s => s.status === 'warning').map((s, i) => (
                  <li key={i}>
                    <strong>{s.name}</strong>: Review {s.requirements_total - s.requirements_met} unmet requirements
                    to improve your compliance score.
                  </li>
                ))}
              </ul>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}