// VulnScope - Targets Component Tests

import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { Targets } from './Targets'

// Mock the hooks
jest.mock('@/lib/hooks/useApi', () => ({
  useTargets: jest.fn(),
  useCreateTarget: jest.fn(),
  useDeleteTarget: jest.fn(),
  useUpdateTarget: jest.fn(),
}))

const mockUseTargets = require('@/lib/hooks/useApi').useTargets
const mockUseCreateTarget = require('@/lib/hooks/useApi').useCreateTarget
const mockUseDeleteTarget = require('@/lib/hooks/useApi').useDeleteTarget

const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('Targets', () => {
  beforeEach(() => {
    jest.clearAllMocks()
    mockUseTargets.mockReturnValue({ data: [], isLoading: false, refetch: jest.fn() })
    mockUseCreateTarget.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
    mockUseDeleteTarget.mockReturnValue({ mutateAsync: jest.fn(), isPending: false })
  })

  it('renders targets page title', () => {
    render(<Targets />, { wrapper: createWrapper() })
    expect(screen.getByText('Targets')).toBeInTheDocument()
    expect(screen.getByText('Manage your scan targets')).toBeInTheDocument()
  })

  it('renders add target button', () => {
    render(<Targets />, { wrapper: createWrapper() })
    expect(screen.getByText('Add Target')).toBeInTheDocument()
  })

  it('renders refresh button', () => {
    render(<Targets />, { wrapper: createWrapper() })
    expect(screen.getByText('Refresh')).toBeInTheDocument()
  })

  it('shows empty state when no targets', () => {
    render(<Targets />, { wrapper: createWrapper() })
    expect(screen.getByText(/No targets yet/)).toBeInTheDocument()
  })

  it('opens create form when clicking add target button', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
  })

  it('closes form when clicking cancel', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.click(screen.getByText('Cancel'))
    
    await waitFor(() => {
      expect(screen.queryByText('Add New Target')).not.toBeInTheDocument()
    })
  })

  it('displays targets table with data', () => {
    mockUseTargets.mockReturnValue({
      data: [
        { id: '1', name: 'Target 1', url: 'http://example1.com', created_at: '2024-01-01T00:00:00Z' },
        { id: '2', name: 'Target 2', url: 'http://example2.com', created_at: '2024-01-02T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Target 1')).toBeInTheDocument()
    expect(screen.getByText('Target 2')).toBeInTheDocument()
  })

  it('displays target URL in table', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test Target', url: 'http://test.example.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('http://test.example.com')).toBeInTheDocument()
  })

  it('displays target tags', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test', url: 'http://test.com', tags: ['production', 'critical'], created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('production')).toBeInTheDocument()
    expect(screen.getByText('critical')).toBeInTheDocument()
  })

  it('displays auth type when present', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test', url: 'http://test.com', auth_type: 'bearer', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('bearer')).toBeInTheDocument()
  })

  it('shows loading state', () => {
    mockUseTargets.mockReturnValue({ data: null, isLoading: true, refetch: jest.fn() })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Chargement...')).toBeInTheDocument()
  })

  it('calls refetch when refresh clicked', () => {
    const mockRefetch = jest.fn()
    mockUseTargets.mockReturnValue({ data: [], isLoading: false, refetch: mockRefetch })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Refresh'))
    
    expect(mockRefetch).toHaveBeenCalled()
  })

  it('renders form inputs when form is open', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText(/Target Name/)).toBeInTheDocument()
      expect(screen.getByText(/Target URL/)).toBeInTheDocument()
    })
  })

  it('renders type select in form', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Web App')).toBeInTheDocument()
    })
  })

  it('renders authentication section in form', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Authentication (Optional)')).toBeInTheDocument()
    })
  })

  it('displays summary stats when targets exist', () => {
    mockUseTargets.mockReturnValue({
      data: [
        { id: '1', name: 'Target 1', url: 'http://example1.com', auth_type: 'bearer', tags: ['prod'], created_at: '2024-01-01T00:00:00Z' },
        { id: '2', name: 'Target 2', url: 'http://example2.com', tags: ['dev'], created_at: '2024-01-02T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Total Targets')).toBeInTheDocument()
    expect(screen.getByText('With Authentication')).toBeInTheDocument()
    expect(screen.getByText('Unique Tags')).toBeInTheDocument()
  })

  it('shows delete button for each target', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test Target', url: 'http://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const deleteButtons = screen.getAllByRole('button')
    const deleteButton = deleteButtons.find(btn => btn.querySelector('svg.lucide-trash-2') || btn.closest('button')?.classList?.contains('hover:bg-muted'))
    expect(deleteButton || screen.getByTitle('Delete')).toBeTruthy()
  })

  it('shows edit button for each target', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test Target', url: 'http://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByTitle('Edit')).toBeInTheDocument()
  })

  it('renders auth type options in form', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('None')).toBeInTheDocument()
    })
  })
})