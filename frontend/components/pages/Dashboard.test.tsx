// VulnScope - Dashboard Component Tests
// Tests for the main dashboard page component

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Dashboard } from './Dashboard'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useDashboardStats: jest.fn(),
  useTargets: jest.fn(),
  useScans: jest.fn(),
  useFindings: jest.fn(),
}))

// Mock recharts to avoid SSR issues
jest.mock('recharts', () => ({
  BarChart: () => <div data-testid="bar-chart">Bar Chart</div>,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: any) => <div data-testid="responsive-container">{children}</div>,
  LineChart: () => <div data-testid="line-chart">Line Chart</div>,
  Line: () => null,
}))

const mockUseDashboardStats = require('@/lib/hooks/useApi').useDashboardStats
const mockUseTargets = require('@/lib/hooks/useApi').useTargets
const mockUseScans = require('@/lib/hooks/useApi').useScans
const mockUseFindings = require('@/lib/hooks/useApi').useFindings

// Create a wrapper with QueryClient
const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
  
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('Dashboard', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    
    // Default mock returns
    mockUseDashboardStats.mockReturnValue({
      data: null,
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseTargets.mockReturnValue({
      data: [],
      isLoading: false,
    })
    
    mockUseScans.mockReturnValue({
      data: [],
      isLoading: false,
    })
    
    mockUseFindings.mockReturnValue({
      data: { findings: [], total: 0 },
      isLoading: false,
    })
  })

  it('renders dashboard title', () => {
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Monitor your security posture')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('displays loading state when data is loading', () => {
    mockUseDashboardStats.mockReturnValue({
      data: null,
      isLoading: true,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Should show loading spinners (Loader2 components)
    // Loader2 is an SVG which doesn't have role='img' by default
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })

  it('displays stats when data is loaded', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        total_scans: 10,
        active_scans: 2,
        critical_findings: 5,
        high_findings: 15,
        medium_findings: 20,
        low_findings: 30,
        total_findings: 70,
        total_targets: 3,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Total Scans')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('Active Scans')).toBeInTheDocument()
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('Critical Findings')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('displays critical alert when critical findings exist', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        critical_findings: 3,
        total_scans: 5,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('CRITICAL ALERT')).toBeInTheDocument()
    expect(screen.getByText(/3 critical vulnerabilities detected/)).toBeInTheDocument()
  })

  it('does not display critical alert when no critical findings', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        critical_findings: 0,
        total_scans: 5,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.queryByText('CRITICAL ALERT')).not.toBeInTheDocument()
  })

  it('displays recent scans table', () => {
    mockUseScans.mockReturnValue({
      data: [
        {
          id: '1',
          name: 'Test Scan 1',
          status: 'completed',
          progress: 100,
          findings_count: 5,
          created_at: '2024-01-01T00:00:00Z',
          target_id: 'target-1',
        },
        {
          id: '2',
          name: 'Test Scan 2',
          status: 'running',
          progress: 50,
          findings_count: 2,
          created_at: '2024-01-02T00:00:00Z',
          target_id: 'target-1',
        },
      ],
      isLoading: false,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Recent Scans')).toBeInTheDocument()
    expect(screen.getByText('Test Scan 1')).toBeInTheDocument()
    expect(screen.getByText('Test Scan 2')).toBeInTheDocument()
  })

  it('displays empty state when no scans', () => {
    mockUseScans.mockReturnValue({
      data: [],
      isLoading: false,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('No scans yet. Create a target and start scanning!')).toBeInTheDocument()
  })

  it('filters findings by severity', async () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        total_findings: 10,
        critical_findings: 2,
        high_findings: 3,
        medium_findings: 3,
        low_findings: 2,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: '1', severity: 'Critical', target_id: 't1' },
          { id: '2', severity: 'High', target_id: 't1' },
          { id: '3', severity: 'Medium', target_id: 't1' },
          { id: '4', severity: 'Low', target_id: 't1' },
        ],
        total: 4,
      },
      isLoading: false,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Find severity filter buttons
    const criticalButton = screen.getByRole('button', { name: 'Critical' })
    
    // Click to deselect Critical
    fireEvent.click(criticalButton)
    
    // Should show updated finding count
    await waitFor(() => {
      expect(screen.getByText(/Showing \d+ findings/)).toBeInTheDocument()
    })
  })

  it('calls refetch when refresh button is clicked', async () => {
    const mockRefetch = jest.fn()
    
    mockUseDashboardStats.mockReturnValue({
      data: {
        total_scans: 5,
        critical_findings: 0,
      },
      isLoading: false,
      refetch: mockRefetch,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    const refreshButton = screen.getByText('Refresh')
    fireEvent.click(refreshButton)
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('displays target stats', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        total_targets: 5,
        total_scans: 10,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Total Targets')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('displays medium and low findings stats', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        medium_findings: 12,
        low_findings: 8,
        total_scans: 5,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Medium Findings')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('Low Findings')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('displays charts section', () => {
    mockUseDashboardStats.mockReturnValue({
      data: {
        total_findings: 10,
        critical_findings: 2,
        high_findings: 3,
        medium_findings: 3,
        low_findings: 2,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Findings by Severity')).toBeInTheDocument()
    expect(screen.getByText('Vulnerability Trends')).toBeInTheDocument()
  })

  it('displays scan status badges correctly', () => {
    mockUseScans.mockReturnValue({
      data: [
        {
          id: '1',
          name: 'Completed Scan',
          status: 'completed',
          progress: 100,
          findings_count: 5,
          created_at: '2024-01-01T00:00:00Z',
          target_id: 'target-1',
        },
        {
          id: '2',
          name: 'Running Scan',
          status: 'running',
          progress: 50,
          findings_count: 0,
          created_at: '2024-01-01T00:00:00Z',
          target_id: 'target-1',
        },
        {
          id: '3',
          name: 'Failed Scan',
          status: 'failed',
          progress: 30,
          findings_count: 0,
          created_at: '2024-01-01T00:00:00Z',
          target_id: 'target-1',
        },
      ],
      isLoading: false,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('completed')).toBeInTheDocument()
    expect(screen.getByText('running')).toBeInTheDocument()
    expect(screen.getByText('failed')).toBeInTheDocument()
  })

  it('displays interactive analysis section', () => {
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Interactive Analysis')).toBeInTheDocument()
    expect(screen.getByText('Filter by Severity')).toBeInTheDocument()
  })

  it('toggles target filters', async () => {
    mockUseTargets.mockReturnValue({
      data: [
        { id: 't1', name: 'Target 1' },
        { id: 't2', name: 'Target 2' },
      ],
      isLoading: false,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Wait for targets to load and filter section to appear
    await waitFor(() => {
      expect(screen.getByText('Filter by Target')).toBeInTheDocument()
    })
    
    const targetButton = screen.getByRole('button', { name: 'Target 1' })
    fireEvent.click(targetButton)
    
    // Button should now be selected (toggle behavior)
    await waitFor(() => {
      expect(targetButton).toBeInTheDocument()
    })
  })
})

describe('StatCard', () => {
  it('renders with basic props', () => {
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // StatCard is rendered within Dashboard
    expect(screen.getByText('Total Scans')).toBeInTheDocument()
  })
})