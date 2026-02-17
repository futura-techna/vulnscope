import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { LoginPage } from './LoginPage'
import * as nextAuthReact from 'next-auth/react'

// Mock next-auth
jest.mock('next-auth/react', () => ({
  signIn: jest.fn(),
  useSession: jest.fn(() => ({ data: null, status: 'unauthenticated' })),
}))

describe('LoginPage', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('should render login form', () => {
    render(<LoginPage />)
    
    expect(screen.getByText('VulnScope')).toBeInTheDocument()
    expect(screen.getByText('Sign in to your account')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter your username')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Enter your password')).toInTheDocument()
  })

  it('should show demo credentials', () => {
    render(<LoginPage />)
    
    expect(screen.getByText('Demo Credentials:')).toBeInTheDocument()
    expect(screen.getByText(/admin/)).toBeInTheDocument()
  })

  it('should show error with invalid credentials', async () => {
    ;(nextAuthReact.signIn as jest.Mock).mockResolvedValue({ error: 'Invalid credentials' })
    
    render(<LoginPage />)
    
    const usernameInput = screen.getByPlaceholderText('Enter your username')
    const passwordInput = screen.getByPlaceholderText('Enter your password')
    const submitButton = screen.getByRole('button', { name: /sign in/i })
    
    fireEvent.change(usernameInput, { target: { value: 'wrong' } })
    fireEvent.change(passwordInput, { target: { value: 'wrong' } })
    fireEvent.click(submitButton)
    
    await waitFor(() => {
      expect(screen.getByText('Invalid username or password')).toBeInTheDocument()
    })
  })

  it('should call signIn on submit', async () => {
    ;(nextAuthReact.signIn as jest.Mock).mockResolvedValue({ error: null })
    
    render(<LoginPage />)
    
    const usernameInput = screen.getByPlaceholderText('Enter your username')
    const passwordInput = screen.getByPlaceholderText('Enter your password')
    const submitButton = screen.getByRole('button', { name: /sign in/i })
    
    fireEvent.change(usernameInput, { target: { value: 'admin' } })
    fireEvent.change(passwordInput, { target: { value: 'admin123' } })
    fireEvent.click(submitButton)
    
    await waitFor(() => {
      expect(nextAuthReact.signIn).toHaveBeenCalledWith('credentials', {
        username: 'admin',
        password: 'admin123',
        redirect: false,
      })
    })
  })

  it('should show loading state while submitting', async () => {
    ;(nextAuthReact.signIn as jest.Mock).mockImplementation(() => new Promise(resolve => setTimeout(resolve, 100)))
    
    render(<LoginPage />)
    
    const usernameInput = screen.getByPlaceholderText('Enter your username')
    const passwordInput = screen.getByPlaceholderText('Enter your password')
    const submitButton = screen.getByRole('button', { name: /sign in/i })
    
    fireEvent.change(usernameInput, { target: { value: 'admin' } })
    fireEvent.change(passwordInput, { target: { value: 'admin123' } })
    fireEvent.click(submitButton)
    
    expect(screen.getByText('Signing in...')).toBeInTheDocument()
    expect(submitButton).toBeDisabled()
  })
})
