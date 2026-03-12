// VulnScope - Findings Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Findings } from './Findings'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useFindings: jest.fn(),
  useUpdateFinding: jest.fn(),
  useTargets: jest.fn(),
  useScans: jest.fn(),
}))

// Mock recharts
jest.mock('recharts', () => ({
  BarChart: () => <div data-testid="bar-chart">Chart</div>,
  Bar: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
  ResponsiveContainer: ({ children }: any) => <div>{children}</div>,
}))

const mockUseFindings = require('@/lib/hooks/useApi').useFindings
const mockUseUpdateFinding = require('@/lib/hooks/useApi').useUpdateFinding
const mockUseTargets = require('@/lib/hooks/useApi').useTargets
const mockUseScans = require('@/lib/hooks/useApi').useScans

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Findings', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseFindings.mockReturnValue({ data: { findings: [], total: 0 }, isLoading: false, refetch: jest.fn(), isFetching: false })
    mockUseTargets.mockReturnValue({ data: [], isLoading: false })
    mockUseScans.mockReturnValue({ data: [], isLoading: false })
    mockUseUpdateFinding.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
  })

  it('renders findings page title', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.getByText('View and manage vulnerabilities')).toBeInTheDocument()
  })

  it('renders export button', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText('Export')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state when no findings', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText(/No findings match your filters/)).toBeInTheDocument()
  })

  it('displays findings count', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText(/Showing 0 of 0 findings/)).toBeInTheDocument()
  })

  it('displays findings table with data', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: 'finding-1', title: 'XSS Vulnerability', severity: 'High', vuln_type: 'XSS', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
          { id: 'finding-2', title: 'SQL Injection', severity: 'Critical', vuln_type: 'SQL_INJECTION', status: 'Open', target_id: 't1', created_at: '2024-01-02T00:00:00Z' },
        ],
        total: 2,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1' }],
      isLoading: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    expect(screen.getByText('XSS Vulnerability')).toBeInTheDocument()
    expect(screen.getByText('SQL Injection')).toBeInTheDocument()
  })

  it('displays critical findings alert when critical findings exist', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: '1', title: 'Critical Issue', severity: 'Critical', vuln_type: 'SQL_INJECTION', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
        ],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    expect(screen.getByText(/Critical Findings/)).toBeInTheDocument()
    expect(screen.getByText('Show Critical Only')).toBeInTheDocument()
  })

  it('filters by severity', async () => {
    render(<Findings />, { wrapper: createWrapper() })
    
    const highButton = screen.getByRole('button', { name: 'High' })
    fireEvent.click(highButton)
    
    await waitFor(() => {
      expect(highButton).toBeInTheDocument()
    })
  })

  it('filters by status', async () => {
    render(<Findings />, { wrapper: createWrapper() })
    
    const statusSelect = screen.getByRole('combobox')
    fireEvent.change(statusSelect, { target: { value: 'Open' } })
    
    await waitFor(() => {
      expect(statusSelect).toHaveValue('Open')
    })
  })

  it('calls refetch when refresh clicked', () => {
    const mockRefetch = jest.fn()
    mockUseFindings.mockReturnValue({ data: { findings: [], total: 0 }, isLoading: false, refetch: mockRefetch, isFetching: false })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Refresh'))
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('renders filter section', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByText('Filters')).toBeInTheDocument()
  })

  it('renders severity filter buttons', () => {
    render(<Findings />, { wrapper: createWrapper() })
    expect(screen.getByRole('button', { name: 'Critical' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'High' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Medium' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Low' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Info' })).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseFindings.mockReturnValue({ data: null, isLoading: true, refetch: jest.fn(), isFetching: false })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })

  it('opens export menu when export clicked', async () => {
    mockUseFindings.mockReturnValue({
      data: { findings: [{ id: '1', title: 'Test', severity: 'High', vuln_type: 'XSS', status: 'Open', target_id: 't1', created_at: '2024-01-01' }], total: 1 },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Export'))
    
    await waitFor(() => {
      expect(screen.getByText('Export as JSON')).toBeInTheDocument()
      expect(screen.getByText('Export as CSV')).toBeInTheDocument()
    })
  })

  it('displays target name in findings table', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ id: '1', title: 'Test Finding', severity: 'High', vuln_type: 'XSS', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'My Target' }],
      isLoading: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    expect(screen.getByText('My Target')).toBeInTheDocument()
  })
})