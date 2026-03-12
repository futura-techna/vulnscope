// VulnScope - Header Component Tests

import React from 'react'
import { render, screen, fireEvent } from '@testing-library/react'
import { Header } from './Header'

describe('Header', () => {
  const mockOnThemeChange = jest.fn()
  const mockOnLogout = jest.fn()
  const mockUser = {
    name: 'Test User',
    email: 'test@example.com',
  }

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders search input', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    expect(screen.getByPlaceholderText('Search targets, findings...')).toBeInTheDocument()
  })

  it('renders notification button', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    const bellButton = document.querySelector('.lucide-bell')
    expect(bellButton).toBeInTheDocument()
  })

  it('renders theme toggle button', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    // Sun icon is shown when theme is dark
    const sunIcon = document.querySelector('.lucide-sun')
    expect(sunIcon).toBeInTheDocument()
  })

  it('renders moon icon when theme is light', () => {
    render(
      <Header
        theme="light"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    const moonIcon = document.querySelector('.lucide-moon')
    expect(moonIcon).toBeInTheDocument()
  })

  it('calls onThemeChange when theme button clicked', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    
    const themeButtons = screen.getAllByRole('button')
    const themeButton = themeButtons.find(btn => btn.querySelector('.lucide-sun') || btn.querySelector('.lucide-moon'))
    
    if (themeButton) {
      fireEvent.click(themeButton)
    }
    
    expect(mockOnThemeChange).toHaveBeenCalledWith('light')
  })

  it('renders user name', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    expect(screen.getByText('Test User')).toBeInTheDocument()
  })

  it('renders user email', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    expect(screen.getByText('test@example.com')).toBeInTheDocument()
  })

  it('renders default user name when not provided', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={null}
        onLogout={mockOnLogout}
      />
    )
    expect(screen.getByText('User')).toBeInTheDocument()
  })

  it('renders default email when not provided', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={null}
        onLogout={mockOnLogout}
      />
    )
    expect(screen.getByText('user@example.com')).toBeInTheDocument()
  })

  it('calls onLogout when logout button clicked', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    
    const logoutButton = screen.getByTitle('Logout')
    fireEvent.click(logoutButton)
    
    expect(mockOnLogout).toHaveBeenCalled()
  })

  it('renders notification indicator', () => {
    render(
      <Header
        theme="dark"
        onThemeChange={mockOnThemeChange}
        user={mockUser}
        onLogout={mockOnLogout}
      />
    )
    const indicator = document.querySelector('.bg-red-500.rounded-full')
    expect(indicator).toBeInTheDocument()
  })
})