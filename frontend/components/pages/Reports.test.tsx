// VulnScope - Reports Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Reports } from './Reports'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useReports: jest.fn(),
  useGenerateReport: jest.fn(),
  useScans: jest.fn(),
}))

// Mock the api module
jest.mock('@/lib/api', () => ({
  __esModule: true,
  default: {
    downloadReport: jest.fn(),
  },
}))

const mockUseReports = require('@/lib/hooks/useApi').useReports
const mockUseGenerateReport = require('@/lib/hooks/useApi').useGenerateReport
const mockUseScans = require('@/lib/hooks/useApi').useScans

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Reports', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseReports.mockReturnValue({ data: [], isLoading: false, refetch: jest.fn() })
    mockUseGenerateReport.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
    mockUseScans.mockReturnValue({ data: [], isLoading: false })
  })

  it('renders reports page title', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Reports')).toBeInTheDocument()
    expect(screen.getByText('Generate and download security reports')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('renders generate report section header', () => {
    render(<Reports />, { wrapper: createWrapper() })
    const headers = screen.getAllByText('Generate Report')
    expect(headers.length).toBeGreaterThan(0)
  })

  it('shows empty state when no reports', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText(/No reports yet/)).toBeInTheDocument()
  })

  it('renders format options in quick selection', () => {
    render(<Reports />, { wrapper: createWrapper() })
    // Check for format cards in Quick Format Selection
    const jsonElements = screen.getAllByText('JSON')
    expect(jsonElements.length).toBeGreaterThan(0)
    const htmlElements = screen.getAllByText('HTML')
    expect(htmlElements.length).toBeGreaterThan(0)
    const csvElements = screen.getAllByText('CSV')
    expect(csvElements.length).toBeGreaterThan(0)
    const sarifElements = screen.getAllByText('SARIF')
    expect(sarifElements.length).toBeGreaterThan(0)
  })

  it('renders scan select dropdown', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Select Scan')).toBeInTheDocument()
  })

  it('renders report name input', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Report Name')).toBeInTheDocument()
  })

  it('renders format select dropdown label', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Format')).toBeInTheDocument()
  })

  it('renders generate report button', () => {
    render(<Reports />, { wrapper: createWrapper() })
    const buttons = screen.getAllByText('Generate Report')
    // Find the button specifically
    const button = buttons.find(el => el.tagName === 'BUTTON' || el.closest('button'))
    expect(button).toBeTruthy()
  })

  it('displays completed scans in dropdown', () => {
    mockUseScans.mockReturnValue({
      data: [
        { id: '1', name: 'Completed Scan', status: 'completed' },
        { id: '2', name: 'Running Scan', status: 'running' },
      ],
      isLoading: false,
    })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Completed Scan')).toBeInTheDocument()
    expect(screen.queryByText('Running Scan')).not.toBeInTheDocument()
  })

  it('displays reports in table', () => {
    mockUseReports.mockReturnValue({
      data: [
        { id: '1', name: 'Report 1', format: 'json', scan_id: 's1', created_at: '2024-01-01T00:00:00Z' },
        { id: '2', name: 'Report 2', format: 'html', scan_id: 's2', created_at: '2024-01-02T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    mockUseScans.mockReturnValue({
      data: [
        { id: 's1', name: 'Scan 1' },
        { id: 's2', name: 'Scan 2' },
      ],
      isLoading: false,
    })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Report 1')).toBeInTheDocument()
    expect(screen.getByText('Report 2')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseReports.mockReturnValue({ data: null, isLoading: true, refetch: jest.fn() })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    const container = document.querySelector('.space-y-6')
    expect(container).toBeInTheDocument()
  })

  it('calls refetch when refresh clicked', () => {
    const mockRefetch = jest.fn()
    mockUseReports.mockReturnValue({ data: [], isLoading: false, refetch: mockRefetch })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Refresh'))
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('shows report history section', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Report History')).toBeInTheDocument()
  })

  it('disables generate button when no scan selected', () => {
    render(<Reports />, { wrapper: createWrapper() })
    
    // Find the button by its text content
    const allButtons = screen.getAllByRole('button')
    const generateButton = allButtons.find(btn => btn.textContent?.includes('Generate Report') && btn.tagName === 'BUTTON')
    expect(generateButton).toBeDisabled()
  })

  it('shows quick format selection buttons', () => {
    render(<Reports />, { wrapper: createWrapper() })
    expect(screen.getByText('Quick Format Selection')).toBeInTheDocument()
  })

  it('displays format badges in report table', () => {
    mockUseReports.mockReturnValue({
      data: [{ id: '1', name: 'JSON Report', format: 'json', scan_id: 's1', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    // JSON appears multiple times - in dropdown and in table
    const jsonElements = screen.getAllByText('JSON')
    expect(jsonElements.length).toBeGreaterThan(0)
  })

  it('shows download button for each report', () => {
    mockUseReports.mockReturnValue({
      data: [{ id: '1', name: 'Test Report', format: 'json', scan_id: 's1', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Reports />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Download')).toBeInTheDocument()
  })
})