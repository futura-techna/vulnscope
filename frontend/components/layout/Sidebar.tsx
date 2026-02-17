'use client'

import { 
  LayoutDashboard, 
  Target, 
  Scan, 
  AlertTriangle, 
  FileCheck, 
  FileText, 
  Settings,
  Shield
} from 'lucide-react'
import { cn } from '@/lib/utils'

type Page = 'dashboard' | 'targets' | 'scans' | 'findings' | 'compliance' | 'reports' | 'settings'

interface SidebarProps {
  currentPage: Page
  onNavigate: (page: Page) => void
}

const navItems: { id: Page; label: string; icon: any }[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'targets', label: 'Targets', icon: Target },
  { id: 'scans', label: 'Scans', icon: Scan },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'compliance', label: 'Compliance', icon: FileCheck },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'settings', label: 'Settings', icon: Settings },
]

export function Sidebar({ currentPage, onNavigate }: SidebarProps) {
  return (
    <aside className="w-64 border-r bg-card text-card-foreground flex flex-col">
      {/* Logo */}
      <div className="flex items-center gap-2 px-6 py-4 border-b">
        <Shield className="h-8 w-8 text-primary" />
        <span className="text-xl font-bold">VulnScope</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map((item) => {
          const Icon = item.icon
          const isActive = currentPage === item.id
          
          return (
            <button
              key={item.id}
              onClick={() => onNavigate(item.id)}
              className={cn(
                'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors',
                isActive
                  ? 'bg-primary text-primary-foreground'
                  : 'text-muted-foreground hover:bg-muted hover:text-foreground'
              )}
            >
              <Icon className="h-5 w-5" />
              {item.label}
            </button>
          )
        })}
      </nav>

      {/* Footer */}
      <div className="px-6 py-4 border-t text-xs text-muted-foreground">
        VulnScope v1.0.0
      </div>
    </aside>
  )
}
