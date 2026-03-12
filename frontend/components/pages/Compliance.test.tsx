// VulnScope - Compliance Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Compliance } from './Compliance'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useCompliance: jest.fn(),
  useComplianceCategories: jest.fn(),
  useFindings: jest.fn(),
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
  Cell: () => null,
}))

const mockUseCompliance = require('@/lib/hooks/useApi').useCompliance
const mockUseComplianceCategories = require('@/lib/hooks/useApi').useComplianceCategories
const mockUseFindings = require('@/lib/hooks/useApi').useFindings

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Compliance', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseCompliance.mockReturnValue({ data: [], isLoading: false, error: null, refetch: jest.fn() })
    mockUseComplianceCategories.mockReturnValue({ data: [], isLoading: false, refetch: jest.fn() })
    mockUseFindings.mockReturnValue({ data: { findings: [], total: 0 }, isLoading: false })
  })

  it('renders compliance page title', () => {
    render(<Compliance />, { wrapper: createWrapper() })
    expect(screen.getByText('Compliance')).toBeInTheDocument()
    expect(screen.getByText('Monitor compliance with security standards')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Compliance />, { wrapper: createWrapper() })
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state when no compliance data', () => {
    render(<Compliance />, { wrapper: createWrapper() })
    expect(screen.getByText(/No compliance data available/)).toBeInTheDocument()
  })

  it('displays compliance details section', () => {
    render(<Compliance />, { wrapper: createWrapper() })
    expect(screen.getByText('Compliance Details')).toBeInTheDocument()
  })

  it('displays standards when data is available', () => {
    mockUseCompliance.mockReturnValue({
      data: [
        { name: 'PCI-DSS', score: 95, status: 'pass', requirements_met: 19, requirements_total: 20 },
        { name: 'NIS2', score: 85, status: 'warning', requirements_met: 17, requirements_total: 20 },
      ],
      isLoading: false,
      error: null,
      refetch: jest.fn(),
    })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    const pciElements = screen.getAllByText('PCI-DSS')
    expect(pciElements.length).toBeGreaterThan(0)
    const nis2Elements = screen.getAllByText('NIS2')
    expect(nis2Elements.length).toBeGreaterThan(0)
  })

  it('displays categories section when data is available', () => {
    mockUseComplianceCategories.mockReturnValue({
      data: [
        { name: 'Access Control', score: 95 },
        { name: 'Encryption', score: 90 },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Compliance by Category')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseCompliance.mockReturnValue({ data: null, isLoading: true, error: null, refetch: jest.fn() })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    // Loading spinner should be in document
    const spinner = document.querySelector('.animate-spin')
    expect(spinner).toBeInTheDocument()
  })

  it('shows error state', () => {
    mockUseCompliance.mockReturnValue({ data: null, isLoading: false, error: 'Network error', refetch: jest.fn() })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Failed to load compliance data')).toBeInTheDocument()
    expect(screen.getByText('Retry')).toBeInTheDocument()
  })

  it('calls refetch when refresh clicked', () => {
    const mockRefetch = jest.fn()
    mockUseCompliance.mockReturnValue({ data: [], isLoading: false, error: null, refetch: mockRefetch })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Refresh'))
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('displays recommendations when status is warning', () => {
    mockUseCompliance.mockReturnValue({
      data: [
        { name: 'GDPR', score: 75, status: 'warning', requirements_met: 15, requirements_total: 20 },
      ],
      isLoading: false,
      error: null,
      refetch: jest.fn(),
    })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Recommendations')).toBeInTheDocument()
  })

  it('displays requirements met in table', () => {
    mockUseCompliance.mockReturnValue({
      data: [
        { name: 'PCI-DSS', score: 95, status: 'pass', requirements_met: 19, requirements_total: 20 },
      ],
      isLoading: false,
      error: null,
      refetch: jest.fn(),
    })
    
    render(<Compliance />, { wrapper: createWrapper() })
    
    expect(screen.getByText('19 / 20')).toBeInTheDocument()
  })
})