'use client'

import { Moon, Sun, LogOut, Bell, Search } from 'lucide-react'
import { cn } from '@/lib/utils'

interface HeaderProps {
  theme: 'light' | 'dark'
  onThemeChange: (theme: 'light' | 'dark') => void
  user: any
  onLogout: () => void
}

export function Header({ theme, onThemeChange, user, onLogout }: HeaderProps) {
  return (
    <header className="border-b bg-card">
      <div className="flex items-center justify-between px-6 py-3">
        {/* Search */}
        <div className="flex items-center gap-2 flex-1 max-w-md">
          <div className="relative w-full">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Search targets, findings..."
              className="w-full pl-10 pr-4 py-2 rounded-lg border bg-background text-sm focus:outline-none focus:ring-2 focus:ring-primary"
            />
          </div>
        </div>

        {/* Actions */}
        <div className="flex items-center gap-4">
          {/* Notifications */}
          <button className="relative p-2 rounded-lg hover:bg-muted transition-colors">
            <Bell className="h-5 w-5 text-muted-foreground" />
            <span className="absolute top-1 right-1 h-2 w-2 bg-red-500 rounded-full"></span>
          </button>

          {/* Theme Toggle */}
          <button
            onClick={() => onThemeChange(theme === 'dark' ? 'light' : 'dark')}
            className="p-2 rounded-lg hover:bg-muted transition-colors"
          >
            {theme === 'dark' ? (
              <Sun className="h-5 w-5 text-muted-foreground" />
            ) : (
              <Moon className="h-5 w-5 text-muted-foreground" />
            )}
          </button>

          {/* User Menu */}
          <div className="flex items-center gap-3 pl-4 border-l">
            <div className="text-right">
              <p className="text-sm font-medium">{user?.name || 'User'}</p>
              <p className="text-xs text-muted-foreground">{user?.email || 'user@example.com'}</p>
            </div>
            <button
              onClick={onLogout}
              className="p-2 rounded-lg hover:bg-muted transition-colors text-muted-foreground hover:text-destructive"
              title="Logout"
            >
              <LogOut className="h-5 w-5" />
            </button>
          </div>
        </div>
      </div>
    </header>
  )
}
