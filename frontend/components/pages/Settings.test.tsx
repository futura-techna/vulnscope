// VulnScope - Settings Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Settings } from './Settings'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useSettings: jest.fn(),
  useUpdateSettings: jest.fn(),
}))

const mockUseSettings = require('@/lib/hooks/useApi').useSettings
const mockUseUpdateSettings = require('@/lib/hooks/useApi').useUpdateSettings

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Settings', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseSettings.mockReturnValue({ data: null, isLoading: false })
    mockUseUpdateSettings.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
  })

  it('renders settings page title', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Settings')).toBeInTheDocument()
    expect(screen.getByText('Configure VulnScope preferences')).toBeInTheDocument()
  })

  it('renders general settings section', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('General')).toBeInTheDocument()
  })

  it('renders scanner settings section', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Scanner')).toBeInTheDocument()
  })

  it('renders notifications settings section', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Notifications')).toBeInTheDocument()
  })

  it('renders theme settings section', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Dashboard Theme')).toBeInTheDocument()
  })

  it('renders save button', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Save Settings')).toBeInTheDocument()
  })

  it('renders API URL input', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('API URL')).toBeInTheDocument()
  })

  it('renders API Key input', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('API Key')).toBeInTheDocument()
  })

  it('renders max concurrent requests input', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Max Concurrent Requests')).toBeInTheDocument()
  })

  it('renders timeout input', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText(/Request Timeout/)).toBeInTheDocument()
  })

  it('renders rate limit input', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText(/Rate Limit/)).toBeInTheDocument()
  })

  it('renders email notifications toggle', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText(/Email notifications for critical findings/)).toBeInTheDocument()
  })

  it('renders slack integration toggle', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText(/Slack integration/)).toBeInTheDocument()
  })

  it('renders theme select', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Default Theme')).toBeInTheDocument()
  })

  it('renders auto-refresh toggle', () => {
    render(<Settings />, { wrapper: createWrapper() })
    expect(screen.getByText('Auto-refresh dashboard')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseSettings.mockReturnValue({ data: null, isLoading: true })
    
    render(<Settings />, { wrapper: createWrapper() })
    
    // Settings page should render even during loading
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('populates form with settings data', async () => {
    mockUseSettings.mockReturnValue({
      data: {
        api_url: 'http://localhost:8000',
        max_concurrent: 20,
        timeout: 60,
        rate_limit: 50,
        email_notifications: false,
        slack_integration: true,
        default_theme: 'light',
        auto_refresh: true,
      },
      isLoading: false,
    })
    
    render(<Settings />, { wrapper: createWrapper() })
    
    await waitFor(() => {
      const apiUrlInput = document.querySelector('input[type="url"]') as HTMLInputElement
      expect(apiUrlInput?.value).toBe('http://localhost:8000')
    })
  })

  it('saves settings when form submitted', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({})
    mockUseUpdateSettings.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Settings />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Save Settings'))
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalled()
    })
  })
})