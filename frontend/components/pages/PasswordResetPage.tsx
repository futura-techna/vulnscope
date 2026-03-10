'use client'

import { useState } from 'react'
import { Shield, Lock, Mail, ArrowLeft, KeyRound } from 'lucide-react'

interface PasswordResetPageProps {
  onBackToLogin: () => void
}

type Step = 'request' | 'confirm'

export function PasswordResetPage({ onBackToLogin }: PasswordResetPageProps) {
  const [step, setStep] = useState<Step>('request')
  const [email, setEmail] = useState('')
  const [token, setToken] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const validatePassword = (pwd: string): string | null => {
    if (pwd.length < 8) return 'Password must be at least 8 characters'
    if (!/[A-Z]/.test(pwd)) return 'Password must contain at least one uppercase letter'
    if (!/[a-z]/.test(pwd)) return 'Password must contain at least one lowercase letter'
    if (!/[0-9]/.test(pwd)) return 'Password must contain at least one digit'
    return null
  }

  const handleRequestReset = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const response = await fetch('/api/auth/password-reset', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ email }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.detail || 'Failed to request password reset')
      } else {
        setSuccess(data.message || 'If an account exists with this email, a password reset link has been sent.')
      }
    } catch (err) {
      setError('An error occurred. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  const handleConfirmReset = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')
    setLoading(true)

    // Validate passwords match
    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      setLoading(false)
      return
    }

    // Validate password strength
    const passwordError = validatePassword(newPassword)
    if (passwordError) {
      setError(passwordError)
      setLoading(false)
      return
    }

    try {
      const response = await fetch('/api/auth/password-reset/confirm', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          token,
          new_password: newPassword,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        setError(data.detail || 'Failed to reset password')
      } else {
        setSuccess(data.message || 'Password has been reset successfully. You can now log in with your new password.')
        setToken('')
        setNewPassword('')
        setConfirmPassword('')
        // Redirect to login after 3 seconds
        setTimeout(() => {
          onBackToLogin()
        }, 3000)
      }
    } catch (err) {
      setError('An error occurred. Please try again.')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-br from-slate-900 via-slate-800 to-slate-900">
      {/* Header Section */}
      <div className="text-center mb-8 max-w-lg">
        <h1 className="text-3xl font-bold text-white mb-4">VulnScope</h1>
        <p className="text-lg text-blue-400 mb-2">Reset your password</p>
        <div className="space-y-1 text-sm text-gray-400 mt-4">
          <p>🔒 Secure password reset</p>
          <p>🛡️ Your account protection guaranteed</p>
        </div>
      </div>

      <div className="w-full max-w-md p-8 bg-card rounded-2xl shadow-2xl border border-border">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-primary/10 rounded-full mb-4">
            <KeyRound className="h-8 w-8 text-primary" />
          </div>
          <h1 className="text-2xl font-bold">
            {step === 'request' ? 'Forgot Password' : 'Reset Password'}
          </h1>
          <p className="text-muted-foreground mt-2">
            {step === 'request' 
              ? 'Enter your email to receive a reset link' 
              : 'Enter your new password'}
          </p>
        </div>

        {/* Back to Login */}
        <button
          onClick={onBackToLogin}
          className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground mb-6 transition-colors"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to login
        </button>

        {/* Step Toggle */}
        <div className="flex mb-6 bg-muted rounded-lg p-1">
          <button
            type="button"
            onClick={() => setStep('request')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              step === 'request' 
                ? 'bg-primary text-primary-foreground' 
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Request Reset
          </button>
          <button
            type="button"
            onClick={() => setStep('confirm')}
            className={`flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors ${
              step === 'confirm' 
                ? 'bg-primary text-primary-foreground' 
                : 'text-muted-foreground hover:text-foreground'
            }`}
          >
            Enter Token
          </button>
        </div>

        {error && (
          <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-lg text-destructive text-sm mb-4">
            {error}
          </div>
        )}

        {success && (
          <div className="p-3 bg-green-500/10 border border-green-500/20 rounded-lg text-green-500 text-sm mb-4">
            {success}
          </div>
        )}

        {/* Request Reset Form */}
        {step === 'request' && (
          <form onSubmit={handleRequestReset} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">Email Address</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="Enter your email"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Sending...' : 'Send Reset Link'}
            </button>
          </form>
        )}

        {/* Confirm Reset Form */}
        {step === 'confirm' && (
          <form onSubmit={handleConfirmReset} className="space-y-4">
            <div>
              <label className="block text-sm font-medium mb-2">Reset Token</label>
              <div className="relative">
                <input
                  type="text"
                  value={token}
                  onChange={(e) => setToken(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary font-mono text-sm"
                  placeholder="Paste your reset token here"
                  required
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Check your email for the reset token
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="Enter new password"
                  required
                  minLength={8}
                />
              </div>
              <p className="text-xs text-muted-foreground mt-1">
                Min 8 chars, 1 uppercase, 1 lowercase, 1 digit
              </p>
            </div>

            <div>
              <label className="block text-sm font-medium mb-2">Confirm New Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <input
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  className="w-full pl-10 pr-4 py-3 rounded-lg border bg-background focus:outline-none focus:ring-2 focus:ring-primary"
                  placeholder="Confirm new password"
                  required
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="w-full py-3 px-4 bg-primary text-primary-foreground rounded-lg font-medium hover:bg-primary/90 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Resetting...' : 'Reset Password'}
            </button>
          </form>
        )}

        {/* Footer */}
        <p className="mt-6 text-center text-sm text-muted-foreground">
          Remember your password?{' '}
          <button
            onClick={onBackToLogin}
            className="text-primary hover:underline"
          >
            Sign in
          </button>
        </p>
      </div>
    </div>
  )
}