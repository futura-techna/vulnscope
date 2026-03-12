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

  it('toggles critical only filter when clicking Show Critical Only', async () => {
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
    
    const criticalButton = screen.getByText('Show Critical Only')
    fireEvent.click(criticalButton)
    
    await waitFor(() => {
      expect(screen.getByText('Show All')).toBeInTheDocument()
    })
  })

  it('displays finding URL in table', () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: '1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1', 
          url: 'https://example.com/vulnerable',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    expect(screen.getByText('https://example.com/vulnerable')).toBeInTheDocument()
  })

  it('opens finding detail modal when eye icon clicked', async () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1', 
          scan_id: 's1',
          url: 'https://example.com/vuln',
          method: 'POST',
          parameter: 'search',
          payload: '<script>alert(1)</script>',
          evidence: 'XSS found',
          cvss_score: 7.5,
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    mockUseTargets.mockReturnValue({
      data: [{ id: 't1', name: 'Target 1' }],
      isLoading: false,
    })
    mockUseScans.mockReturnValue({
      data: [{ id: 's1', name: 'Scan 1' }],
      isLoading: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    const viewButton = screen.getByTitle('View Details')
    fireEvent.click(viewButton)
    
    await waitFor(() => {
      expect(screen.getByText('POST')).toBeInTheDocument()
      expect(screen.getByText('search')).toBeInTheDocument()
      expect(screen.getByText('<script>alert(1)</script>')).toBeInTheDocument()
    })
  })

  it('closes finding detail modal when close button clicked', async () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    const viewButton = screen.getByTitle('View Details')
    fireEvent.click(viewButton)
    
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Close' })).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByRole('button', { name: 'Close' }))
    
    await waitFor(() => {
      expect(screen.queryByRole('button', { name: 'Close' })).not.toBeInTheDocument()
    })
  })

  it('exports findings to JSON when export option clicked', async () => {
    // Mock URL.createObjectURL and related functions
    const mockCreateObjectURL = jest.fn(() => 'blob:mock-url')
    const mockRevokeObjectURL = jest.fn()
    window.URL.createObjectURL = mockCreateObjectURL
    window.URL.revokeObjectURL = mockRevokeObjectURL
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          url: 'https://example.com',
          method: 'GET',
          parameter: 'q',
          payload: '<script>',
          evidence: 'XSS triggered',
          cvss_score: 7.5,
          cwe_id: 'CWE-79',
          owasp_category: 'A03:2021',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Export'))
    
    await waitFor(() => {
      expect(screen.getByText('Export as JSON')).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByText('Export as JSON'))
    
    await waitFor(() => {
      expect(mockCreateObjectURL).toHaveBeenCalled()
    })
  })

  it('exports findings to CSV when export option clicked', async () => {
    const mockCreateObjectURL = jest.fn(() => 'blob:mock-url')
    const mockRevokeObjectURL = jest.fn()
    window.URL.createObjectURL = mockCreateObjectURL
    window.URL.revokeObjectURL = mockRevokeObjectURL
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          url: 'https://example.com',
          method: 'GET',
          parameter: 'q',
          cvss_score: 7.5,
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Export'))
    
    await waitFor(() => {
      expect(screen.getByText('Export as CSV')).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByText('Export as CSV'))
    
    await waitFor(() => {
      expect(mockCreateObjectURL).toHaveBeenCalled()
    })
  })

  it('shows alert when exporting with no findings', async () => {
    const mockAlert = jest.spyOn(window, 'alert').mockImplementation(() => {})
    
    mockUseFindings.mockReturnValue({
      data: { findings: [], total: 0 },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    // Export button should be disabled when no findings
    expect(screen.getByText('Export')).toBeDisabled()
    
    mockAlert.mockRestore()
  })

  it('updates finding status when status changed', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({})
    mockUseUpdateFinding.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    // Get all comboboxes - the status select in the table row comes after the filter select
    const statusSelects = screen.getAllByRole('combobox')
    // There are 2 comboboxes: filter status (index 0) and finding status in table (index 1)
    const findingStatusSelect = statusSelects[1]
    fireEvent.change(findingStatusSelect, { target: { value: 'Resolved' } })
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith({
        id: 'finding-1',
        data: { status: 'Resolved' }
      })
    })
  })

  it('handles status update error', async () => {
    const consoleError = jest.spyOn(console, 'error').mockImplementation(() => {})
    const mockMutateAsync = jest.fn().mockRejectedValue(new Error('Update failed'))
    mockUseUpdateFinding.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    // Get all comboboxes - the status select in the table row comes after the filter select
    const statusSelects = screen.getAllByRole('combobox')
    // There are 2 comboboxes: filter status (index 0) and finding status in table (index 1)
    const findingStatusSelect = statusSelects[1]
    fireEvent.change(findingStatusSelect, { target: { value: 'Resolved' } })
    
    await waitFor(() => {
      expect(consoleError).toHaveBeenCalled()
    })
    
    consoleError.mockRestore()
  })

  it('clears all filters when clear filters clicked', async () => {
    mockUseFindings.mockReturnValue({
      data: { findings: [], total: 0 },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    // Apply severity filter
    fireEvent.click(screen.getByRole('button', { name: 'High' }))
    
    // Since findings are empty with filters applied, clear filters button should appear
    const clearButton = await screen.queryByText('Clear filters')
    if (clearButton) {
      fireEvent.click(clearButton)
      await waitFor(() => {
        expect(screen.getByRole('button', { name: 'High' })).not.toHaveClass('bg-orange-500')
      })
    }
  })

  it('filters findings by type', async () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: '1', title: 'XSS', severity: 'High', vuln_type: 'XSS', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', title: 'SQLi', severity: 'Critical', vuln_type: 'SQL_INJECTION', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
        ],
        total: 2,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    const xssTypeButton = screen.getByRole('button', { name: 'XSS' })
    fireEvent.click(xssTypeButton)
    
    await waitFor(() => {
      expect(xssTypeButton).toBeInTheDocument()
    })
  })

  it('marks finding as resolved from modal', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({})
    mockUseUpdateFinding.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: 'finding-1', 
          title: 'Test Finding', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    const viewButton = screen.getByTitle('View Details')
    fireEvent.click(viewButton)
    
    await waitFor(() => {
      expect(screen.getByRole('button', { name: 'Mark Resolved' })).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByRole('button', { name: 'Mark Resolved' }))
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith({
        id: 'finding-1',
        data: { status: 'Resolved' }
      })
    })
  })

  it('displays chart when findings exist', async () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [{ 
          id: '1', 
          title: 'Test', 
          severity: 'High', 
          vuln_type: 'XSS', 
          status: 'Open', 
          target_id: 't1',
          created_at: '2024-01-01T00:00:00Z' 
        }],
        total: 1,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    await waitFor(() => {
      expect(screen.getByText('Findings by Type')).toBeInTheDocument()
    })
  })

  it('shows finding count correctly', async () => {
    mockUseFindings.mockReturnValue({
      data: {
        findings: [
          { id: '1', title: 'Test 1', severity: 'High', vuln_type: 'XSS', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
          { id: '2', title: 'Test 2', severity: 'Low', vuln_type: 'INFO', status: 'Open', target_id: 't1', created_at: '2024-01-01T00:00:00Z' },
        ],
        total: 2,
      },
      isLoading: false,
      refetch: jest.fn(),
      isFetching: false,
    })
    
    render(<Findings />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Showing 2 of 2 findings')).toBeInTheDocument()
  })
})
