'use client'

import { useState, useEffect } from 'react'
import { Save, Settings as SettingsIcon, Bell, Key, Palette, Scan, Loader2, CheckCircle } from 'lucide-react'
import { useSettings, useUpdateSettings } from '@/lib/hooks/useApi'

export function Settings() {
  const [formData, setFormData] = useState({
    api_url: '',
    api_key: '',
    max_concurrent: 10,
    timeout: 30,
    rate_limit: 100,
    email_notifications: true,
    slack_integration: false,
    default_theme: 'dark' as 'light' | 'dark',
    auto_refresh: false,
  })
  const [saved, setSaved] = useState(false)

  // Fetch settings using React Query
  const { data: settings, isLoading } = useSettings()
  const updateSettings = useUpdateSettings()

  // Update form when settings load
  useEffect(() => {
    if (settings) {
      setFormData({
        api_url: settings.api_url || '',
        api_key: '', // Don't show existing API key
        max_concurrent: settings.max_concurrent || 10,
        timeout: settings.timeout || 30,
        rate_limit: settings.rate_limit || 100,
        email_notifications: settings.email_notifications ?? true,
        slack_integration: settings.slack_integration ?? false,
        default_theme: settings.default_theme || 'dark',
        auto_refresh: settings.auto_refresh ?? false,
      })
    }
  }, [settings])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      await updateSettings.mutateAsync({
        api_url: formData.api_url,
        max_concurrent: formData.max_concurrent,
        timeout: formData.timeout,
        rate_limit: formData.rate_limit,
        email_notifications: formData.email_notifications,
        slack_integration: formData.slack_integration,
        default_theme: formData.default_theme,
        auto_refresh: formData.auto_refresh,
      })
      
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    } catch (error) {
      console.error('Failed to save settings:', error)
      alert('Failed to save settings. Please try again.')
    }
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Page Title */}
      <div>
        <h1 className="text-3xl font-bold">Settings</h1>
        <p className="text-muted-foreground mt-1">Configure VulnScope preferences</p>
      </div>

      {/* Success Message */}
      {saved && (
        <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-xl flex items-center gap-3">
          <CheckCircle className="h-5 w-5 text-green-500" />
          <p className="text-green-500">Settings saved successfully!</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* General Settings */}
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3 mb-6">
            <SettingsIcon className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">General</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">API URL</label>
              <input
                type="url"
                value={formData.api_url}
                onChange={(e) => setFormData({ ...formData, api_url: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="http://localhost:8000/api/v1"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">API Key</label>
              <input
                type="password"
                value={formData.api_key}
                onChange={(e) => setFormData({ ...formData, api_key: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Enter your API key"
              />
              <p className="text-xs text-muted-foreground mt-1">Leave empty to keep existing key</p>
            </div>
          </div>
        </div>

        {/* Scanner Settings */}
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3 mb-6">
            <Scan className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Scanner</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Max Concurrent Requests</label>
              <input
                type="number"
                value={formData.max_concurrent}
                onChange={(e) => setFormData({ ...formData, max_concurrent: parseInt(e.target.value) || 10 })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                min={1}
                max={100}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Request Timeout (seconds)</label>
              <input
                type="number"
                value={formData.timeout}
                onChange={(e) => setFormData({ ...formData, timeout: parseInt(e.target.value) || 30 })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                min={5}
                max={120}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Rate Limit (req/sec)</label>
              <input
                type="number"
                value={formData.rate_limit}
                onChange={(e) => setFormData({ ...formData, rate_limit: parseInt(e.target.value) || 100 })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                min={1}
                max={1000}
              />
            </div>
          </div>
        </div>

        {/* Notification Settings */}
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3 mb-6">
            <Bell className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Notifications</h2>
          </div>
          
          <div className="space-y-4">
            <label className="flex items-center justify-between p-4 border rounded-lg cursor-pointer hover:bg-muted/50">
              <div>
                <p className="font-medium">Email notifications for critical findings</p>
                <p className="text-sm text-muted-foreground">Receive email alerts when critical vulnerabilities are found</p>
              </div>
              <input
                type="checkbox"
                checked={formData.email_notifications}
                onChange={(e) => setFormData({ ...formData, email_notifications: e.target.checked })}
                className="rounded border-gray-300 h-5 w-5"
              />
            </label>
            
            <label className="flex items-center justify-between p-4 border rounded-lg cursor-pointer hover:bg-muted/50">
              <div>
                <p className="font-medium">Slack integration</p>
                <p className="text-sm text-muted-foreground">Send notifications to Slack channels</p>
              </div>
              <input
                type="checkbox"
                checked={formData.slack_integration}
                onChange={(e) => setFormData({ ...formData, slack_integration: e.target.checked })}
                className="rounded border-gray-300 h-5 w-5"
              />
            </label>
          </div>
        </div>

        {/* Dashboard Theme */}
        <div className="bg-card rounded-xl p-6 border">
          <div className="flex items-center gap-3 mb-6">
            <Palette className="h-5 w-5 text-muted-foreground" />
            <h2 className="text-lg font-semibold">Dashboard Theme</h2>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium mb-2">Default Theme</label>
              <select
                value={formData.default_theme}
                onChange={(e) => setFormData({ ...formData, default_theme: e.target.value as 'light' | 'dark' })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
              >
                <option value="light">Light</option>
                <option value="dark">Dark</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">&nbsp;</label>
              <label className="flex items-center gap-3 p-4 border rounded-lg cursor-pointer hover:bg-muted/50 h-[46px]">
                <input
                  type="checkbox"
                  checked={formData.auto_refresh}
                  onChange={(e) => setFormData({ ...formData, auto_refresh: e.target.checked })}
                  className="rounded border-gray-300 h-5 w-5"
                />
                <span className="font-medium">Auto-refresh dashboard</span>
              </label>
            </div>
          </div>
        </div>

        {/* Save Button */}
        <div className="flex justify-end">
          <button
            type="submit"
            disabled={updateSettings.isPending}
            className="flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90 disabled:opacity-50"
          >
            {updateSettings.isPending ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Saving...
              </>
            ) : (
              <>
                <Save className="h-4 w-4" />
                Save Settings
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  )
}