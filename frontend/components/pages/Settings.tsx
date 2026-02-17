'use client'

import { useState } from 'react'
import { Save, Settings as SettingsIcon, Bell, Key, Palette, Scan } from 'lucide-react'

export function Settings() {
  const [formData, setFormData] = useState({
    apiUrl: 'http://localhost:8000/api/v1',
    apiKey: '',
    maxConcurrent: 10,
    timeout: 30,
    rateLimit: 100,
    emailNotifications: true,
    slackIntegration: false,
    defaultTheme: 'dark',
    autoRefresh: false,
  })
  const [saved, setSaved] = useState(false)

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    // Save settings
    console.log('Saving settings:', formData)
    setSaved(true)
    setTimeout(() => setSaved(false), 3000)
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
        <div className="p-4 bg-green-500/10 border border-green-500/20 rounded-xl">
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
                value={formData.apiUrl}
                onChange={(e) => setFormData({ ...formData, apiUrl: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="http://localhost:8000/api/v1"
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">API Key</label>
              <input
                type="password"
                value={formData.apiKey}
                onChange={(e) => setFormData({ ...formData, apiKey: e.target.value })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                placeholder="Enter your API key"
              />
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
                value={formData.maxConcurrent}
                onChange={(e) => setFormData({ ...formData, maxConcurrent: parseInt(e.target.value) })}
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
                onChange={(e) => setFormData({ ...formData, timeout: parseInt(e.target.value) })}
                className="w-full px-4 py-2 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                min={5}
                max={120}
              />
            </div>
            <div>
              <label className="block text-sm font-medium mb-2">Rate Limit (req/sec)</label>
              <input
                type="number"
                value={formData.rateLimit}
                onChange={(e) => setFormData({ ...formData, rateLimit: parseInt(e.target.value) })}
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
                checked={formData.emailNotifications}
                onChange={(e) => setFormData({ ...formData, emailNotifications: e.target.checked })}
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
                checked={formData.slackIntegration}
                onChange={(e) => setFormData({ ...formData, slackIntegration: e.target.checked })}
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
                value={formData.defaultTheme}
                onChange={(e) => setFormData({ ...formData, defaultTheme: e.target.value })}
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
                  checked={formData.autoRefresh}
                  onChange={(e) => setFormData({ ...formData, autoRefresh: e.target.checked })}
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
            className="flex items-center gap-2 px-6 py-3 bg-primary text-primary-foreground rounded-lg hover:bg-primary/90"
          >
            <Save className="h-4 w-4" />
            Save Settings
          </button>
        </div>
      </form>
    </div>
  )
}
