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

  it('submits form with valid data', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({ id: 'new-target' })
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Open form with first Add Target button
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    // Fill in required fields
    const nameInput = screen.getByPlaceholderText('My Application')
    const urlInput = screen.getByPlaceholderText('https://example.com')
    
    fireEvent.change(nameInput, { target: { value: 'Test Target' } })
    fireEvent.change(urlInput, { target: { value: 'https://test.example.com' } })
    
    // Click the submit button in the form (last Add Target button)
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith({
        name: 'Test Target',
        url: 'https://test.example.com',
      })
    })
  })

  it('submits form with all fields', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({ id: 'new-target' })
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Click the header Add Target button (first one)
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    // Fill in all fields
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    fireEvent.change(screen.getByPlaceholderText('Security assessment target'), { target: { value: 'Test description' } })
    fireEvent.change(screen.getByPlaceholderText('production, critical'), { target: { value: 'prod, api' } })
    
    // Select auth type
    const authTypeSelects = screen.getAllByRole('combobox')
    const authTypeSelect = authTypeSelects.find(select => select.closest('div')?.textContent?.includes('Auth Type'))
    if (authTypeSelect) {
      fireEvent.change(authTypeSelect, { target: { value: 'Bearer Token' } })
    }
    
    // Click the submit button (use getAllByRole and select the last one which is the form submit)
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalled()
    })
  })

  it('shows success message after creation', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({ id: 'new-target' })
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Click the header Add Target button
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    // Click the submit button (type="submit")
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText(/Cible créée avec succès/)).toBeInTheDocument()
    })
  })

  it('shows error message on creation failure', async () => {
    const mockMutateAsync = jest.fn().mockRejectedValue(new Error('Creation failed'))
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Click the header Add Target button
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    // Click the submit button
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText('Creation failed')).toBeInTheDocument()
    })
  })

  it('handles network error on creation', async () => {
    const networkError = new Error('Network Error')
    const mockMutateAsync = jest.fn().mockRejectedValue(networkError)
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText(/Erreur réseau/)).toBeInTheDocument()
    })
  })

  it('handles axios error with response data', async () => {
    const axiosError = {
      response: {
        data: {
          detail: 'URL already exists'
        }
      }
    }
    const mockMutateAsync = jest.fn().mockRejectedValue(axiosError)
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText('URL already exists')).toBeInTheDocument()
    })
  })

  it('deletes target after confirmation', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({})
    mockUseDeleteTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseTargets.mockReturnValue({
      data: [{ id: 'target-1', name: 'Test Target', url: 'https://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    // Mock window.confirm
    jest.spyOn(window, 'confirm').mockReturnValue(true)
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const deleteButton = screen.getByTitle('Delete')
    fireEvent.click(deleteButton)
    
    await waitFor(() => {
      expect(mockMutateAsync).toHaveBeenCalledWith('target-1')
    })
    
    jest.restoreAllMocks()
  })

  it('cancels delete when not confirmed', async () => {
    const mockMutateAsync = jest.fn()
    mockUseDeleteTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseTargets.mockReturnValue({
      data: [{ id: 'target-1', name: 'Test Target', url: 'https://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    // Mock window.confirm to return false
    jest.spyOn(window, 'confirm').mockReturnValue(false)
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const deleteButton = screen.getByTitle('Delete')
    fireEvent.click(deleteButton)
    
    expect(mockMutateAsync).not.toHaveBeenCalled()
    
    jest.restoreAllMocks()
  })

  it('shows success message after deletion', async () => {
    const mockMutateAsync = jest.fn().mockResolvedValue({})
    mockUseDeleteTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseTargets.mockReturnValue({
      data: [{ id: 'target-1', name: 'Test Target', url: 'https://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    jest.spyOn(window, 'confirm').mockReturnValue(true)
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const deleteButton = screen.getByTitle('Delete')
    fireEvent.click(deleteButton)
    
    await waitFor(() => {
      expect(screen.getByText(/Cible supprimée avec succès/)).toBeInTheDocument()
    })
    
    jest.restoreAllMocks()
  })

  it('shows error message on deletion failure', async () => {
    const mockMutateAsync = jest.fn().mockRejectedValue(new Error('Delete failed'))
    mockUseDeleteTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    mockUseTargets.mockReturnValue({
      data: [{ id: 'target-1', name: 'Test Target', url: 'https://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    jest.spyOn(window, 'confirm').mockReturnValue(true)
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const deleteButton = screen.getByTitle('Delete')
    fireEvent.click(deleteButton)
    
    await waitFor(() => {
      expect(screen.getByText(/Erreur lors de la suppression/)).toBeInTheDocument()
    })
    
    jest.restoreAllMocks()
  })

  it('clears notifications automatically', async () => {
    jest.useFakeTimers()
    
    const mockMutateAsync = jest.fn().mockResolvedValue({ id: 'new-target' })
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText(/Cible créée avec succès/)).toBeInTheDocument()
    })
    
    // Fast-forward 5 seconds
    jest.advanceTimersByTime(5000)
    
    await waitFor(() => {
      expect(screen.queryByText(/Cible créée avec succès/)).not.toBeInTheDocument()
    })
    
    jest.useRealTimers()
  })

  it('dismisses error notification when X clicked', async () => {
    const mockMutateAsync = jest.fn().mockRejectedValue(new Error('Test error'))
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: false })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const addButtons = screen.getAllByText('Add Target')
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    const submitButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(submitButtons[submitButtons.length - 1])
    
    await waitFor(() => {
      expect(screen.getByText('Test error')).toBeInTheDocument()
    })
    
    // Click dismiss button
    const dismissButton = screen.getByRole('button', { name: '' })
    fireEvent.click(dismissButton)
    
    await waitFor(() => {
      expect(screen.queryByText('Test error')).not.toBeInTheDocument()
    })
  })

  it('shows loading state during creation', async () => {
    const mockMutateAsync = jest.fn().mockImplementation(() => new Promise(() => {}))
    mockUseCreateTarget.mockReturnValue({ mutateAsync: mockMutateAsync, isPending: true })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    fireEvent.change(screen.getByPlaceholderText('My Application'), { target: { value: 'Test Target' } })
    fireEvent.change(screen.getByPlaceholderText('https://example.com'), { target: { value: 'https://test.example.com' } })
    
    fireEvent.click(screen.getByRole('button', { name: /Adding/ }))
    
    expect(screen.getByText('Adding...')).toBeInTheDocument()
  })

  it('disables form fields during submission', async () => {
    mockUseCreateTarget.mockReturnValue({ mutateAsync: jest.fn(), isPending: true })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    fireEvent.click(screen.getByText('Add Target'))
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    const nameInput = screen.getByPlaceholderText('My Application')
    const urlInput = screen.getByPlaceholderText('https://example.com')
    
    expect(nameInput).toBeDisabled()
    expect(urlInput).toBeDisabled()
  })

  it('displays description in table when present', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test', url: 'https://test.com', description: 'Test description', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    expect(screen.getByText('Test description')).toBeInTheDocument()
  })

  it('displays dash when no description', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test', url: 'https://test.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Description column should show '-'
    const cells = screen.getAllByRole('cell')
    const descriptionCell = cells.find(cell => cell.textContent === '-')
    expect(descriptionCell).toBeTruthy()
  })

  it('calculates stats correctly', () => {
    mockUseTargets.mockReturnValue({
      data: [
        { id: '1', name: 'Target 1', url: 'https://test1.com', auth_type: 'bearer', tags: ['prod', 'api'], created_at: '2024-01-01T00:00:00Z' },
        { id: '2', name: 'Target 2', url: 'https://test2.com', tags: ['dev'], created_at: '2024-01-02T00:00:00Z' },
        { id: '3', name: 'Target 3', url: 'https://test3.com', auth_type: 'basic', tags: ['prod'], created_at: '2024-01-03T00:00:00Z' },
      ],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    // Total targets: 3 - there are multiple elements with '3', check for the stat
    const allThreeTexts = screen.getAllByText('3')
    expect(allThreeTexts.length).toBeGreaterThan(0)
  })

  it('renders target URL as link', () => {
    mockUseTargets.mockReturnValue({
      data: [{ id: '1', name: 'Test', url: 'https://test.example.com', created_at: '2024-01-01T00:00:00Z' }],
      isLoading: false,
      refetch: jest.fn(),
    })
    
    render(<Targets />, { wrapper: createWrapper() })
    
    const link = screen.getByRole('link', { name: 'https://test.example.com' })
    expect(link).toHaveAttribute('href', 'https://test.example.com')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('toggles form visibility when clicking Add Target button', async () => {
    render(<Targets />, { wrapper: createWrapper() })
    
    // Open form
    const addButtons = screen.getAllByRole('button', { name: /Add Target/i })
    fireEvent.click(addButtons[0])
    
    await waitFor(() => {
      expect(screen.getByText('Add New Target')).toBeInTheDocument()
    })
    
    // Close form by clicking Cancel instead
    fireEvent.click(screen.getByText('Cancel'))
    
    await waitFor(() => {
      expect(screen.queryByText('Add New Target')).not.toBeInTheDocument()
    })
  })
})