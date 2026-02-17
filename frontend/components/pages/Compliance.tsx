'use client'

import { FileCheck, CheckCircle, AlertTriangle } from 'lucide-react'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { cn } from '@/lib/utils'

const standards = [
  { name: 'PCI-DSS', score: 95, status: 'pass' },
  { name: 'NIS2', score: 78, status: 'warning' },
  { name: 'SOC2', score: 92, status: 'pass' },
  { name: 'HIPAA', score: 88, status: 'warning' },
  { name: 'ISO27001', score: 85, status: 'warning' },
]

const categories = [
  { name: 'Access Control', score: 92 },
  { name: 'Encryption', score: 88 },
  { name: 'Monitoring', score: 95 },
  { name: 'Incident Response', score: 78 },
  { name: 'Vendor Management', score: 85 },
]

export function Compliance() {
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

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-3xl font-bold">Compliance</h1>
        <p className="text-muted-foreground mt-1">Monitor compliance with security standards</p>
      </div>

      {/* Standards Overview */}
      <div className="grid grid-cols-1 md:grid-cols-5 gap-4">
        {standards.map((standard, i) => (
          <div key={i} className="bg-card rounded-xl p-6 border">
            <div className="flex items-center justify-between mb-4">
              <span className="font-medium">{standard.name}</span>
              {getStatusIcon(standard.status)}
            </div>
            <div className="text-3xl font-bold" style={{ color: getScoreColor(standard.score) }}>
              {standard.score}%
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

      {/* Compliance by Category */}
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
            />
            <Bar dataKey="score" radius={[0, 4, 4, 0]}>
              {categories.map((entry, index) => (
                <Cell key={`cell-${index}`} fill={getScoreColor(entry.score)} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* Detailed Standards */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="p-6 border-b">
          <h2 className="text-lg font-semibold">Compliance Details</h2>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left py-3 px-4 font-medium">Standard</th>
                <th className="text-left py-3 px-4 font-medium">Score</th>
                <th className="text-left py-3 px-4 font-medium">Status</th>
                <th className="text-left py-3 px-4 font-medium">Requirements Met</th>
                <th className="text-left py-3 px-4 font-medium">Requirements Total</th>
              </tr>
            </thead>
            <tbody>
              {[
                { name: 'PCI-DSS', score: 95, met: 19, total: 20 },
                { name: 'NIS2', score: 78, met: 25, total: 32 },
                { name: 'SOC2', score: 92, met: 46, total: 50 },
                { name: 'HIPAA', score: 88, met: 44, total: 50 },
                { name: 'ISO27001', score: 85, met: 68, total: 80 },
              ].map((item, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4 font-medium">{item.name}</td>
                  <td className="py-3 px-4">
                    <span 
                      className="font-bold"
                      style={{ color: getScoreColor(item.score) }}
                    >
                      {item.score}%
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {getStatusIcon(item.score >= 90 ? 'pass' : 'warning')}
                  </td>
                  <td className="py-3 px-4">{item.met}</td>
                  <td className="py-3 px-4 text-muted-foreground">{item.total}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
