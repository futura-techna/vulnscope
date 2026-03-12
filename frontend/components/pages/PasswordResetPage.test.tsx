// VulnScope - PasswordResetPage Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { PasswordResetPage } from './PasswordResetPage'

// Mock fetch
global.fetch = jest.fn()

describe('PasswordResetPage', () => {
  const mockOnBackToLogin = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should render password reset form', () => {
    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByText(/reset your password/i)).toBeInTheDocument()
    expect(screen.getByPlaceholderText(/enter your email/i)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /send reset link/i })).toBeInTheDocument()
  })

  it('should submit email for password reset', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'Reset email sent' })
    })

    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    const emailInput = screen.getByPlaceholderText(/enter your email/i)
    const submitButton = screen.getByRole('button', { name: /send reset link/i })
    
    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
    fireEvent.click(submitButton)
    
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith(
        '/api/auth/password-reset',
        expect.objectContaining({ method: 'POST' })
      )
    })
  })

  it('should handle API error', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ detail: 'Email not found' })
    })

    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    const emailInput = screen.getByPlaceholderText(/enter your email/i)
    const submitButton = screen.getByRole('button', { name: /send reset link/i })
    
    fireEvent.change(emailInput, { target: { value: 'notfound@example.com' } })
    fireEvent.click(submitButton)
    
    await waitFor(() => {
      expect(screen.getByText(/email not found/i)).toBeInTheDocument()
    })
  })

  it('should show success message after reset', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: async () => ({ message: 'Reset email sent successfully' })
    })

    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    const emailInput = screen.getByPlaceholderText(/enter your email/i)
    const submitButton = screen.getByRole('button', { name: /send reset link/i })
    
    fireEvent.change(emailInput, { target: { value: 'test@example.com' } })
    fireEvent.click(submitButton)
    
    await waitFor(() => {
      expect(screen.getByText(/email sent/i)).toBeInTheDocument()
    })
  })

  it('should have link to login page', () => {
    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByText(/back to login/i)).toBeInTheDocument()
  })

  it('should call onBackToLogin when back button clicked', () => {
    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    const backButton = screen.getByText(/back to login/i)
    fireEvent.click(backButton)
    
    expect(mockOnBackToLogin).toHaveBeenCalled()
  })

  it('should switch to confirm step', () => {
    render(<PasswordResetPage onBackToLogin={mockOnBackToLogin} />)
    
    const enterTokenTab = screen.getByRole('button', { name: /enter token/i })
    fireEvent.click(enterTokenTab)
    
    expect(screen.getByPlaceholderText(/paste your reset token/i)).toBeInTheDocument()
  })
})