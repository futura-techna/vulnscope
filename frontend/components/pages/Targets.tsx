'use client'

import { useState, useEffect } from 'react'
import { Plus, Globe, Server, Key, Trash2, Edit, Loader2, RefreshCw, X } from 'lucide-react'
import { cn, formatDate } from '@/lib/utils'
import { useTargets, useCreateTarget, useDeleteTarget } from '@/lib/hooks/useApi'
import { TargetCreate } from '@/lib/api'

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
  const [editingTarget, setEditingTarget] = useState<string | null>(null)
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

  // Use React Query hooks
  const { data: targets, isLoading, refetch } = useTargets()
  const createTarget = useCreateTarget()
  const deleteTarget = useDeleteTarget()

  // Clear notifications after 5 seconds
  useEffect(() => {
    if (error || success) {
      const timer = setTimeout(() => {
        setError(null)
        setSuccess(null)
      }, 5000)
      return () => clearTimeout(timer)
    }
  }, [error, success])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSuccess(null)

    const payload: TargetCreate = {
      name: formData.name,
      url: formData.url,
      description: formData.description || undefined,
      tags: formData.tags ? formData.tags.split(',').map(t => t.trim()).filter(Boolean) : undefined,
      auth_type: formData.authType === 'None' ? undefined : formData.authType.toLowerCase().replace(' ', '_'),
      auth_config: formData.authValue ? { value: formData.authValue } : undefined,
    }

    try {
      await createTarget.mutateAsync(payload)
      
      setSuccess('Cible créée avec succès!')
      setShowForm(false)
      resetForm()
    } catch (err) {
      console.error('[Targets] Error creating target:', err)
      if (err instanceof Error) {
        setError(err.message)
      } else {
        setError('Une erreur inattendue s\'est produite.')
      }
    }
  }

  const handleDelete = async (targetId: string) => {
    if (!confirm('Êtes-vous sûr de vouloir supprimer cette cible?')) {
      return
    }

    try {
      await deleteTarget.mutateAsync(targetId)
      setSuccess('Cible supprimée avec succès!')
    } catch (err) {
      console.error('[Targets] Error deleting target:', err)
      setError('Erreur lors de la suppression.')
    }
  }

  const resetForm = () => {
    setFormData({
      name: '',
      url: '',
      type: 'Web App',
      description: '',
      tags: '',
      authType: 'None',
      authValue: '',
    })
    setEditingTarget(null)
  }

  return (
    <div className="space-y-6">
      {/* Notifications */}
      {error && (
        <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive flex items-center justify-between">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="p-1 hover:bg-destructive/20 rounded">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}
      {success && (
        <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-lg text-green-600 flex items-center justify-between">
          <span>{success}</span>
          <button onClick={() => setSuccess(null)} className="p-1 hover:bg-green-500/20 rounded">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {/* Page Title */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Targets</h1>
          <p className="text-muted-foreground mt-1">Manage your scan targets</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="flex items-center gap-2 px-4 py-2 border rounded-lg hover:bg-muted"
          >
            <RefreshCw className="h-4 w-4" />
            Refresh
          </button>
          <button
            onClick={() => {
              setShowForm(!showForm)
              if (showForm) resetForm()
            }}
            className="flex items-center gap-2 px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
          >
            <Plus className="h-4 w-4" />
            Add Target
          </button>
        </div>
      </div>

      {/* Add Target Form */}
      {showForm && (
        <div className="bg-card rounded-xl p-6 border">
          <h2 className="text-lg font-semibold mb-4">
            {editingTarget ? 'Edit Target' : 'Add New Target'}
          </h2>
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
                  disabled={createTarget.isPending}
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
                  disabled={createTarget.isPending}
                />
              </div>
              <div>
                <label className="block text-sm font-medium mb-2">Type</label>
                <select
                  value={formData.type}
                  onChange={(e) => setFormData({ ...formData, type: e.target.value })}
                  className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  disabled={createTarget.isPending}
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
                  disabled={createTarget.isPending}
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
                  disabled={createTarget.isPending}
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
                    disabled={createTarget.isPending}
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
                    disabled={createTarget.isPending || formData.authType === 'None'}
                  />
                </div>
              </div>
            </div>

            <div className="flex justify-end gap-3">
              <button
                type="button"
                onClick={() => {
                  setShowForm(false)
                  resetForm()
                }}
                className="px-4 py-2 border rounded-lg hover:bg-muted"
                disabled={createTarget.isPending}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createTarget.isPending}
                className="px-4 py-2 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
              >
                {createTarget.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                {createTarget.isPending ? 'Adding...' : 'Add Target'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Targets List */}
      <div className="bg-card rounded-xl border overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
            <span className="ml-2 text-muted-foreground">Chargement...</span>
          </div>
        ) : targets && targets.length === 0 ? (
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
                  <th className="text-left py-3 px-4 font-medium">Auth</th>
                  <th className="text-left py-3 px-4 font-medium">Created</th>
                  <th className="text-left py-3 px-4 font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {targets?.map((target) => (
                  <tr key={target.id} className="border-b hover:bg-muted/50">
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-3">
                        <Globe className="h-5 w-5 text-muted-foreground" />
                        <span className="font-medium">{target.name}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <a 
                        href={target.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-primary hover:underline"
                      >
                        {target.url}
                      </a>
                    </td>
                    <td className="py-3 px-4 text-muted-foreground">{target.description || '-'}</td>
                    <td className="py-3 px-4">
                      <div className="flex flex-wrap gap-1">
                        {target.tags?.map((tag, i) => (
                          <span key={i} className="px-2 py-1 bg-muted rounded-full text-xs">{tag}</span>
                        ))}
                        {(!target.tags || target.tags.length === 0) && '-'}
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      {target.auth_type ? (
                        <span className="px-2 py-1 bg-blue-500/10 text-blue-500 rounded-full text-xs">
                          {target.auth_type}
                        </span>
                      ) : '-'}
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
                          disabled={deleteTarget.isPending}
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

      {/* Summary Stats */}
      {targets && targets.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="bg-card rounded-xl p-4 border">
            <p className="text-sm text-muted-foreground">Total Targets</p>
            <p className="text-2xl font-bold">{targets.length}</p>
          </div>
          <div className="bg-card rounded-xl p-4 border">
            <p className="text-sm text-muted-foreground">With Authentication</p>
            <p className="text-2xl font-bold">{targets.filter(t => t.auth_type).length}</p>
          </div>
          <div className="bg-card rounded-xl p-4 border">
            <p className="text-sm text-muted-foreground">Unique Tags</p>
            <p className="text-2xl font-bold">
              {new Set(targets.flatMap(t => t.tags || [])).size}
            </p>
          </div>
        </div>
      )}
    </div>
  )
}