'use client'

import { useState, useEffect } from 'react'
import { Plus, Globe, Server, Key, Trash2, Edit, Loader2 } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'

interface Target {
  id: string
  name: string
  url: string
  description?: string
  tags?: string[]
  auth_type?: string
  created_at: string
}

interface TargetFormData {
  name: string
  url: string
  type: string
  description: string
  tags: string
  authType: string
  authValue: string
}

export function Targets() {
  const [showForm, setShowForm] = useState(false)
  const [targets, setTargets] = useState<Target[]>([])
  const [loading, setLoading] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [formData, setFormData] = useState<TargetFormData>({
    name: '',
    url: '',
    type: 'Web App',
    description: '',
    tags: '',
    authType: 'None',
    authValue: '',
  })

  // Fetch targets on mount
  useEffect(() => {
    fetchTargets()
  }, [])

  const fetchTargets = async () => {
    setLoading(true)
    setError(null)
    try {
      const response = await fetch('/api/targets', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      })

      if (response.ok) {
        const data = await response.json()
        setTargets(data)
      } else {
        console.error('Failed to fetch targets:', response.status)
      }
    } catch (err) {
      console.error('Error fetching targets:', err)
    } finally {
      setLoading(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setSubmitting(true)
    setError(null)
    setSuccess(null)

    try {
      const payload = {
        name: formData.name,
        url: formData.url,
        description: formData.description || null,
        tags: formData.tags ? formData.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
        auth_type: formData.authType === 'None' ? null : formData.authType.toLowerCase().replace(' ', '_'),
        auth_config: formData.authValue ? { value: formData.authValue } : null,
      }

      console.log('[Targets] Creating target:', payload)

      const response = await fetch('/api/targets', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(payload),
      })

      const contentType = response.headers.get('content-type')
      
      if (!contentType || !contentType.includes('application/json')) {
        const textResponse = await response.text()
        console.error('[Targets] Non-JSON response:', textResponse.substring(0, 500))
        throw new Error('Erreur de communication avec le serveur.')
      }

      const data = await response.json()

      if (!response.ok) {
        console.error('[Targets] Error response:', data)
        throw new Error(data.detail || 'Erreur lors de la création de la cible.')
      }

      console.log('[Targets] Target created successfully:', data)
      
      // Add to local state
      setTargets(prev => [...prev, data])
      
      // Reset form
      setFormData({
        name: '',
        url: '',
        type: 'Web App',
        description: '',
        tags: '',
        authType: 'None',
        authValue: '',
      })
      
      setSuccess('Cible créée avec succès!')
      setShowForm(false)
      
      // Refresh targets list
      fetchTargets()
      
    } catch (err) {
      console.error('[Targets] Error creating target:', err)
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Une erreur inattendue s\'est produite.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (targetId: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette cible?')) {
      return
    }

    try {
      const response = await fetch(`/api/targets/${targetId}`, {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      })

      if (response.ok) {
        setTargets(prev => prev.filter(t => t.id !== targetId))
        setSuccess('Cible supprimée avec succès!')
      } else {
        throw new Error('Erreur lors de la suppression.')
      }
    } catch (err) {
      console.error('[Targets] Error deleting target:', err)
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Erreur lors de la suppression.')
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Notifications */}
      {error && (
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive">
          {error}
          <button onClick={() => setError(null)} className="ml-4 text-sm underline">Fermer</button>
        </div>
      )}
      {success && (
        <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-green-600">
          {success}
          <button onClick={() => setSuccess(null)} className="ml-4 text-sm underline">Fermer</button>
        </div>
      )}

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
                <label className="block text-sm font-medium mb-2">Target Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="My Application"
                  required
                  disabled={submitting}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Target URL *</label>
                <input
                  type="url"
                  value={formData.url}
                  onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="https://example.com"
                  required
                  disabled={submitting}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  disabled={submitting}
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
                  disabled={submitting}
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
                  disabled={submitting}
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
                    disabled={submitting}
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
                    disabled={submitting}
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => setShowForm(false)}
                className="px-4 py-2 border rounded-lg hover:bg-muted"
                disabled={submitting}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={submitting}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {submitting && <Loader2 className="h-4 w-4 animate-spin" />}
                {submitting ? 'Adding...' : 'Add Target'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Targets List */}
      <div className="bg-card rounded-xl border overflow-hidden">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">Chargement...</span>
          </div>
        ) : targets.length === 0 ? (
          <div className="text-center py-12 text-muted-foreground">
            <Server className="h-12 w-12 mx-auto mb-4 opacity-50" />
            <p>No targets yet. Click "Add Target" to create one.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b bg-muted/50">
                  <th className="text-left py-3 px-4 font-medium">Name</th>
                  <th className="text-left py-3 px-4 font-medium">URL</th>
                  <th className="text-left py-3 px-4 font-medium">Description</th>
                  <th className="text-left py-3 px-4 font-medium">Tags</th>
                  <th className="text-left py-3 px-4 font-medium">Created</th>
                  <th className="text-left py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets.map((target) => (
                  <tr key={target.id} className="border-b hover:bg-muted/50">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-5 w-5 text-muted-foreground" />
                        <span className="font-medium">{target.name}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4 text-muted-foreground">{target.url}</td>
                    <td className="py-3 px-4 text-muted-foreground">{target.description || '-'}</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {target.tags?.map((tag, i) => (
                          <span key={i} className="px-2 py-1 bg-muted rounded-full text-xs">{tag}</span>
                        ))}
                      </div>
                    </td>
                    <td className="py-3 px-4 text-muted-foreground">{formatDate(target.created_at)}</td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <button className="p-2 hover:bg-muted rounded-lg" title="Edit">
                          <Edit className="h-4 w-4 text-muted-foreground" />
                        </button>
                        <button 
                          onClick={() => handleDelete(target.id)}
                          className="p-2 hover:bg-muted rounded-lg" 
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4 text-destructive" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}