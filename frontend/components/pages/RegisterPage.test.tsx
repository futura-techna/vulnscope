// VulnScope - RegisterPage Component Tests
// Tests for the user registration page

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RegisterPage } from './RegisterPage'

// Mock fetch
global.fetch = jest.fn()

// Helper to fill form
async function fillForm(inputs: { [key: string]: string }) {
  for (const [placeholder, value] of Object.entries(inputs)) {
    const input = screen.getByPlaceholderText(placeholder)
    fireEvent.change(input, { target: { value } })
  }
}

describe('RegisterPage', () => {
  const mockOnBackToLogin = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
    ;(global.fetch as jest.Mock).mockClear()
  })

  it('renders registration form', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getAllByText('Create Account').length).toBeGreaterThan(0)
    expect(screen.getByText('Join VulnScope today')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Choose a username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter your email')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter your full name')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Create a password')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Confirm your password')).toBeInTheDocument()
  })

  it('renders back to login button', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    const backButton = screen.getByText('Back to login')
    expect(backButton).toBeInTheDocument()
  })

  it('calls onBackToLogin when back button is clicked', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    const backButton = screen.getByText('Back to login')
    fireEvent.click(backButton)
    
    expect(mockOnBackToLogin).toHaveBeenCalledTimes(1)
  })

  it('renders create account button', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByRole('button', { name: /create account/i })).toBeInTheDocument()
  })

  it('shows password requirements hint', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByText(/min 8 chars, 1 uppercase, 1 lowercase, 1 digit/i)).toBeInTheDocument()
  })

  it('shows error when passwords do not match', async () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'DifferentPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Passwords do not match')).toBeInTheDocument()
    })
  })

  it('shows error when password is too short', async () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'Short1' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'Short1' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Password must be at least 8 characters')).toBeInTheDocument()
    })
  })

  it('shows error when password has no uppercase', async () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'alllowercase123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'alllowercase123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Password must contain at least one uppercase letter')).toBeInTheDocument()
    })
  })

  it('shows error when password has no lowercase', async () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ALLUPPERCASE123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ALLUPPERCASE123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Password must contain at least one lowercase letter')).toBeInTheDocument()
    })
  })

  it('shows error when password has no digit', async () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'NoDigitHere' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'NoDigitHere' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Password must contain at least one digit')).toBeInTheDocument()
    })
  })

  it('submits form with valid data', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        message: 'Registration successful! Please check your email.',
        username: 'testuser',
        email: 'test@example.com'
      })
    })
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: 'testuser',
          email: 'test@example.com',
          password: 'ValidPass123',
          full_name: undefined
        })
      })
    })
  })

  it('shows success message after successful registration', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        message: 'Registration successful! Please check your email to verify your account.',
        username: 'testuser',
        email: 'test@example.com'
      })
    })
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText(/Registration successful/)).toBeInTheDocument()
    })
  })

  it('shows error message when registration fails', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: false,
      json: () => Promise.resolve({
        detail: 'Username already registered'
      })
    })
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'existinguser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('Username already registered')).toBeInTheDocument()
    })
  })

  it('shows error when network request fails', async () => {
    ;(global.fetch as jest.Mock).mockRejectedValueOnce(new Error('Network error'))
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByText('An error occurred. Please try again.')).toBeInTheDocument()
    })
  })

  it('disables submit button while loading', async () => {
    ;(global.fetch as jest.Mock).mockImplementation(() => new Promise(() => {}))
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /creating account/i })).toBeDisabled()
    })
  })

  it('includes full name in submission when provided', async () => {
    ;(global.fetch as jest.Mock).mockResolvedValueOnce({
      ok: true,
      json: () => Promise.resolve({
        message: 'Registration successful!'
      })
    })
    
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    fireEvent.change(screen.getByPlaceholderText('Choose a username'), { target: { value: 'testuser' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your email'), { target: { value: 'test@example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Enter your full name'), { target: { value: 'Test User' } })
    fireEvent.change(screen.getByPlaceholderText('Create a password'), { target: { value: 'ValidPass123' } })
    fireEvent.change(screen.getByPlaceholderText('Confirm your password'), { target: { value: 'ValidPass123' } })
    
    fireEvent.click(screen.getByRole('button', { name: /create account/i }))
    
    await waitFor(() => {
      expect(global.fetch).toHaveBeenCalledWith('/api/auth/register', expect.objectContaining({
        body: JSON.stringify({
          username: 'testuser',
          email: 'test@example.com',
          password: 'ValidPass123',
          full_name: 'Test User'
        })
      }))
    })
  })

  it('renders security info', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByText(/Secured with end-to-end encryption/i)).toBeInTheDocument()
    expect(screen.getByText(/Data protection guaranteed/i)).toBeInTheDocument()
  })

  it('renders terms and privacy policy notice', () => {
    render(<RegisterPage onBackToLogin={mockOnBackToLogin} />)
    
    expect(screen.getByText(/Terms of Service and Privacy Policy/i)).toBeInTheDocument()
  })
})