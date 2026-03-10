'use client'

import { useState } from 'react'
import { useSession, signIn, signOut } from 'next-auth/react'
import { Sidebar } from '@/components/layout/Sidebar'
import { Header } from '@/components/layout/Header'
import { Dashboard } from '@/components/pages/Dashboard'
import { Targets } from '@/components/pages/Targets'
import { Scans } from '@/components/pages/Scans'
import { Findings } from '@/components/pages/Findings'
import { Compliance } from '@/components/pages/Compliance'
import { Reports } from '@/components/pages/Reports'
import { Settings } from '@/components/pages/Settings'
import { LoginPage } from '@/components/pages/LoginPage'
import { RegisterPage } from '@/components/pages/RegisterPage'
import { PasswordResetPage } from '@/components/pages/PasswordResetPage'

type Page = 'dashboard' | 'targets' | 'scans' | 'findings' | 'compliance' | 'reports' | 'settings'
type AuthPage = 'login' | 'register' | 'reset-password'

export default function Home() {
  const { data: session, status } = useSession()
  const [currentPage, setCurrentPage] = useState<Page>('dashboard')
  const [theme, setTheme] = useState<'light' | 'dark'>('dark')
  const [authPage, setAuthPage] = useState<AuthPage>('login')

  // Show loading while checking auth
  if (status === 'loading') {
    return (
      <div className="flex h-screen items-center justify-center bg-background">
        <div className="text-center">
          <div className="h-12 w-12 animate-spin rounded-full border-4 border-primary border-t-transparent mx-auto"></div>
          <p className="mt-4 text-muted-foreground">Loading...</p>
        </div>
      </div>
    )
  }

  // Show auth pages if not authenticated
  if (!session) {
    switch (authPage) {
      case 'register':
        return <RegisterPage onBackToLogin={() => setAuthPage('login')} />
      case 'reset-password':
        return <PasswordResetPage onBackToLogin={() => setAuthPage('login')} />
      default:
        return (
          <LoginPage 
            onRegister={() => setAuthPage('register')}
            onForgotPassword={() => setAuthPage('reset-password')}
          />
        )
    }
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard':
        return <Dashboard />
      case 'targets':
        return <Targets />
      case 'scans':
        return <Scans />
      case 'findings':
        return <Findings />
      case 'compliance':
        return <Compliance />
      case 'reports':
        return <Reports />
      case 'settings':
        return <Settings />
      default:
        return <Dashboard />
    }
  }

  return (
    <div className={`flex h-screen ${theme === 'dark' ? 'dark' : ''}`}>
      <div className="flex h-full w-full bg-background text-foreground">
        <Sidebar currentPage={currentPage} onNavigate={setCurrentPage} />
        <div className="flex flex-1 flex-col overflow-hidden">
          <Header 
            theme={theme} 
            onThemeChange={setTheme}
            user={session.user}
            onLogout={() => signOut()}
          />
          <main className="flex-1 overflow-y-auto p-6">
            {renderPage()}
          </main>
        </div>
      </div>
    </div>
  )
}
