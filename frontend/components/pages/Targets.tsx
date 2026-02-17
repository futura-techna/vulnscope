'use client'

import { useState } from 'react'
import { Plus, Globe, Server, Key, Trash2, Edit } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

const targetsData = [
  { Name: 'Production App', URL: 'https://app.example.com', Type: 'Web App', LastScan: '2024-01-15' },
  { Name: 'Dev Environment', URL: 'https://dev.example.com', Type: 'Web App', LastScan: '2024-01-14' },
  { Name: 'API Gateway', URL: 'https://api.example.com', Type: 'REST API', LastScan: '2024-01-13' },
]

export function Targets() {
  const [showForm, setShowForm] = useState(false)
  const [formData, setFormData] = useState({
    name: '',
    url: '',
    type: 'Web App',
    description: '',
    tags: '',
    authType: 'None',
    authValue: '',
  })

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Handle form submission
    console.log('Creating target:', formData)
    setShowForm(false)
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Targets</h1>
          <p className="text-muted-foreground mt-1">Manage your scan targets</p>
        </div>
        <button
          onClick={() => setShowForm(!showForm)}
          className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
        >
          <Plus className="h-4 w-4" />
          Add Target
        </button>
      </div>

      {/* Add Target Form */}
      {showForm && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">Add New Target</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-2">Target Name</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="My Application"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Target URL</label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="https://example.com"
                  required
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                >
                  <option>Web App</option>
                  <option>REST API</option>
                  <option>GraphQL API</option>
                  <option>Mobile App</option>
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Description</label>
                <input
                  type="text"
                  value={formData.description}
                  onChange={(e) => setFormData({ ...formData, description: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="Security assessment target"
                />
              </div>
              <div className="md:col-span-2">
                <label className="block text-sm font-medium mb-2">Tags (comma separated)</label>
                <input
                  type="text"
                  value={formData.tags}
                  onChange={(e) => setFormData({ ...formData, tags: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="production, critical"
                />
              </div>
            </div>

            {/* Authentication Section */}
            <div className="border-t pt-4 mt-4">
              <h3 className="font-medium mb-4 flex items-center gap-2">
                <Key className="h-4 w-4" />
                Authentication (Optional)
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Auth Type</label>
                  <select
                    value={formData.authType}
                    onChange={(e) => setFormData({ ...formData, authType: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  >
                    <option>None</option>
                    <option>Basic</option>
                    <option>Bearer Token</option>
                    <option>API Key</option>
                    <option>OAuth2</option>
                  </select>
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Auth Value</label>
                  <input
                    type="password"
                    value={formData.authValue}
                    onChange={(e) => setFormData({ ...formData, authValue: e.target.value })}
                    className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                    placeholder="Enter auth value"
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
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
              >
                Add Target
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Targets List */}
      <div className="bg-card rounded-xl border overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left py-3 px-4 font-medium">Name</th>
                <th className="text-left py-3 px-4 font-medium">URL</th>
                <th className="text-left py-3 px-4 font-medium">Type</th>
                <th className="text-left py-3 px-4 font-medium">Last Scan</th>
                <th className="text-left py-3 px-4 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {targetsData.map((target, i) => (
                <tr key={i} className="border-b hover:bg-muted/50">
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-3">
                      <Globe className="h-5 w-5 text-muted-foreground" />
                      <span className="font-medium">{target.Name}</span>
                    </div>
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">{target.URL}</td>
                  <td className="py-3 px-4">
                    <span className="px-2 py-1 bg-muted rounded-full text-xs">{target.Type}</span>
                  </td>
                  <td className="py-3 px-4 text-muted-foreground">{formatDate(target.LastScan)}</td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <button className="p-2 hover:bg-muted rounded-lg" title="Edit">
                        <Edit className="h-4 w-4 text-muted-foreground" />
                      </button>
                      <button className="p-2 hover:bg-muted rounded-lg" title="Delete">
                        <Trash2 className="h-4 w-4 text-destructive" />
                      </button>
                    </div>
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
