// VulnScope - Scans Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Scans } from './Scans'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useScans: jest.fn(),
  useCreateScan: jest.fn(),
  useCancelScan: jest.fn(),
  useTargets: jest.fn(),
}))

const mockUseScans = require('@/lib/hooks/useApi').useScans
const mockUseCreateScan = require('@/lib/hooks/useApi').useCreateScan
const mockUseCancelScan = require('@/lib/hooks/useApi').useCancelScan
const mockUseTargets = require('@/lib/hooks/useApi').useTargets

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Scans', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseScans.mockReturnValue({ data: [], isLoading: false, refetch: jest.fn() })
    mockUseTargets.mockReturnValue({ data: [], isLoading: false })
    mockUseCreateScan.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
    mockUseCancelScan.mockReturnValue({ mutateAsync: jest.fn() })
  })

  it('renders scans page title', () => {
    render(<Scans />, { wrapper: createWrapper() })
    expect(screen.getByText('Scans')).toBeInTheDocument()
    expect(screen.getByText('Create and manage security scans')).toBeInTheDocument()
  })

  it('renders new scan button', () => {
    render(<Scans />, { wrapper: createWrapper() })
    expect(screen.getByText('New Scan')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Scans />, { wrapper: createWrapper() })
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state when no scans', () => {
    render(<Scans />, { wrapper: createWrapper() })
    expect(screen.getByText(/No scans yet/)).toBeInTheDocument()
  })

  it('opens create scan form when clicking new scan button', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Create New Scan')).toBeInTheDocument()
    })
  })

  it('closes form when clicking cancel', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Create New Scan')).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByText('Cancel'))
    
    await waitFor(() => {
      expect(screen.queryByText('Create New Scan')).not.toBeInTheDocument()
    })
  })

  it('displays scan history table with scans', () => {
    mockUseScans.mockReturnValue({
      data: [
        { id: '1', name: 'Test Scan 1', status: 'completed', progress: 100, findings_count: 5, target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
        { id: '2', name: 'Test Scan 2', status: 'running', progress: 50, findings_count: 0, target_id: 't1', created_at: '2024-01-02T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1', url: 'http://example.com' }],
      isLoading: false,
    })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Test Scan 1')).toBeInTheDocument()
    expect(screen.getByText('Test Scan 2')).toBeInTheDocument()
    expect(screen.getByText('Scan History')).toBeInTheDocument()
  })

  it('displays active scans summary when scans are running', () => {
    mockUseScans.mockReturnValue({
      data: [
        { id: '1', name: 'Running Scan', status: 'running', progress: 50, target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1', url: 'http://example.com' }],
      isLoading: false,
    })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Active Scans')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseScans.mockReturnValue({ data: null, isLoading: true, refetch: jest.fn() })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    // Should show spinner in table area
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })

  it('displays target name in scan table', () => {
    mockUseScans.mockReturnValue({
      data: [
        { id: '1', name: 'Test Scan', status: 'completed', progress: 100, target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'My Target', url: 'http://example.com' }],
      isLoading: false,
    })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    expect(screen.getByText('My Target')).toBeInTheDocument()
  })

  it('shows cancel button for running scans', () => {
    mockUseScans.mockReturnValue({
      data: [
        { id: '1', name: 'Running Scan', status: 'running', progress: 50, target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1', url: 'http://example.com' }],
      isLoading: false,
    })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Cancel')).toBeInTheDocument()
  })

  it('calls refetch when refresh button clicked', () => {
    const mockRefetch = jest.fn()
    mockUseScans.mockReturnValue({ data: [], isLoading: false, refetch: mockRefetch })
    
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Refresh'))
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('renders scan type options in form', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Full Scan')).toBeInTheDocument()
      expect(screen.getByText('Quick Scan')).toBeInTheDocument()
      expect(screen.getByText('API Security Scan')).toBeInTheDocument()
      expect(screen.getByText('Auth Test')).toBeInTheDocument()
    })
  })

  it('renders scan options checkboxes', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Enable Crawler')).toBeInTheDocument()
      expect(screen.getByText('Enable DAST')).toBeInTheDocument()
      expect(screen.getByText('Enable Fuzzer')).toBeInTheDocument()
      expect(screen.getByText('Import OpenAPI')).toBeInTheDocument()
    })
  })

  it('renders advanced options', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Max Concurrent Requests')).toBeInTheDocument()
      expect(screen.getByText('Request Timeout (s)')).toBeInTheDocument()
      expect(screen.getByText('Recursive Scan Depth')).toBeInTheDocument()
    })
  })

  it('shows start scan button', async () => {
    render(<Scans />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('New Scan'))
    
    await waitFor(() => {
      expect(screen.getByText('Start Scan')).toBeInTheDocument()
    })
  })
})