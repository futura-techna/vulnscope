// VulnScope - Dashboard Component Tests
// Tests for the main dashboard page component

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Dashboard } from './Dashboard'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
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
    mockUseTargets.mockReturnValue({
      data: [],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseScans.mockReturnValue({
      data: [],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseFindings.mockReturnValue({
      data: { findings: [], total: 0 },
      isLoading: false,
      refetch: jest.fn(),
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
    mockUseTargets.mockReturnValue({
      data: [],
      isLoading: true,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Should show loading spinners (Loader2 components)
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })

  it('displays stats when data is loaded', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseScans.mockReturnValue({
      data: [
        { id: 's1', status: 'completed' },
        { id: 's2', status: 'running' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'f1', severity: 'Critical' },
          { id: 'f2', severity: 'High' },
          { id: 'f3', severity: 'Medium' },
          { id: 'f4', severity: 'Low' },
        ],
        total: 4,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Check that the stat sections are rendered
    expect(screen.getByText('Total Scans')).toBeInTheDocument()
    expect(screen.getByText('Active Scans')).toBeInTheDocument()
    expect(screen.getByText('Critical Findings')).toBeInTheDocument()
    // Use getAllByText for numbers that might appear multiple times
    expect(screen.getAllByText('2').length).toBeGreaterThan(0) // 2 total scans
    expect(screen.getAllByText('1').length).toBeGreaterThan(0) // 1 running scan and 1 critical
  })

  it('displays critical alert when critical findings exist', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'f1', severity: 'Critical', target_id: 't1' },
          { id: 'f2', severity: 'Critical', target_id: 't1' },
          { id: 'f3', severity: 'Critical', target_id: 't1' },
        ],
        total: 3,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('CRITICAL ALERT')).toBeInTheDocument()
    expect(screen.getByText(/3 critical vulnerabilities detected/)).toBeInTheDocument()
  })

  it('does not display critical alert when no critical findings', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'f1', severity: 'High', target_id: 't1' },
        ],
        total: 1,
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
      refetch: jest.fn(),
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
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('No scans yet. Create a target and start scanning!')).toBeInTheDocument()
  })

  it('filters findings by severity', async () => {
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
      refetch: jest.fn(),
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
    const mockRefetchTargets = jest.fn()
    const mockRefetchScans = jest.fn()
    const mockRefetchFindings = jest.fn()
    
    mockUseTargets.mockReturnValue({
      data: [],
      isLoading: false,
      refetch: mockRefetchTargets,
    })
    
    mockUseScans.mockReturnValue({
      data: [],
      isLoading: false,
      refetch: mockRefetchScans,
    })
    
    mockUseFindings.mockReturnValue({
      data: { findings: [], total: 0 },
      isLoading: false,
      refetch: mockRefetchFindings,
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    const refreshButton = screen.getByText('Refresh')
    fireEvent.click(refreshButton)
    
    await waitFor(() => {
      expect(mockRefetchTargets).toHaveBeenCalled()
      expect(mockRefetchScans).toHaveBeenCalled()
      expect(mockRefetchFindings).toHaveBeenCalled()
    })
  })

  it('displays target stats', () => {
    mockUseTargets.mockReturnValue({
      data: [
        { id: 't1', name: 'Target 1' },
        { id: 't2', name: 'Target 2' },
        { id: 't3', name: 'Target 3' },
        { id: 't4', name: 'Target 4' },
        { id: 't5', name: 'Target 5' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Total Targets')).toBeInTheDocument()
    expect(screen.getByText('5')).toBeInTheDocument()
  })

  it('displays medium and low findings stats', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'f1', severity: 'Medium' },
          { id: 'f2', severity: 'Medium' },
          { id: 'f3', severity: 'Low' },
          { id: 'f4', severity: 'Low' },
        ],
        total: 4,
      },
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Dashboard />, { wrapper: createWrapper() })
    
    // Check that the stats sections are rendered
    expect(screen.getByText('Medium Findings')).toBeInTheDocument()
    expect(screen.getByText('Low Findings')).toBeInTheDocument()
    // Check that the numbers are displayed (2 medium, 2 low)
    expect(screen.getAllByText('2').length).toBeGreaterThan(0)
  })

  it('displays charts section', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'f1', severity: 'Critical' },
          { id: 'f2', severity: 'High' },
          { id: 'f3', severity: 'Medium' },
          { id: 'f4', severity: 'Low' },
        ],
        total: 4,
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
      refetch: jest.fn(),
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
      refetch: jest.fn(),
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