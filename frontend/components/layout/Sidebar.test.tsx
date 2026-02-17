import { render, screen, fireEvent } from '@testing-library/react'
import { Sidebar } from './Sidebar'

describe('Sidebar', () => {
  const mockOnNavigate = jest.fn()

  beforeEach(() => {
    mockOnNavigate.mockClear()
  })

  it('should render navigation items', () => {
    render(<Sidebar currentPage="dashboard" onNavigate={mockOnNavigate} />)
    
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
    expect(screen.getByText('Targets')).toBeInTheDocument()
    expect(screen.getByText('Scans')).toBeInTheDocument()
    expect(screen.getByText('Findings')).toBeInTheDocument()
    expect(screen.getByText('Compliance')).toBeInTheDocument()
    expect(screen.getByText('Reports')).toBeInTheDocument()
    expect(screen.getByText('Settings')).toBeInTheDocument()
  })

  it('should render VulnScope logo', () => {
    render(<Sidebar currentPage="dashboard" onNavigate={mockOnNavigate} />)
    
    expect(screen.getByText('VulnScope')).toBeInTheDocument()
  })

  it('should highlight current page', () => {
    render(<Sidebar currentPage="dashboard" onNavigate={mockOnNavigate} />)
    
    const dashboardButton = screen.getByText('Dashboard').closest('button')
    expect(dashboardButton).toHaveClass('bg-primary')
  })

  it('should call onNavigate when clicking nav item', () => {
    render(<Sidebar currentPage="dashboard" onNavigate={mockOnNavigate} />)
    
    fireEvent.click(screen.getByText('Targets'))
    expect(mockOnNavigate).toHaveBeenCalledWith('targets')
  })

  it('should render version footer', () => {
    render(<Sidebar currentPage="dashboard" onNavigate={mockOnNavigate} />)
    
    expect(screen.getByText('VulnScope v1.0.0')).toBeInTheDocument()
  })
})
