import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import Home from './page'

// Mock next-auth
const mockSignOut = jest.fn()
const mockSignIn = jest.fn()
jest.mock('next-auth/react', () => ({
  useSession: jest.fn(),
  signIn: () => mockSignIn(),
  signOut: () => mockSignOut(),
}))

// Mock next/navigation
const mockPush = jest.fn()
jest.mock('next/navigation', () => ({
  useSearchParams: () => ({
    get: jest.fn(),
  }),
  useRouter: () => ({
    push: mockPush,
  }),
}))

// Mock layout components
jest.mock('@/components/layout/Sidebar', () => ({
  Sidebar: ({ currentPage, onNavigate }: { currentPage: string; onNavigate: (page: string) => void }) => (
    <div data-testid="sidebar">
      <span data-testid="current-page">{currentPage}</span>
      <button onClick={() => onNavigate('targets')}>Targets</button>
      <button onClick={() => onNavigate('scans')}>Scans</button>
      <button onClick={() => onNavigate('findings')}>Findings</button>
    </div>
  ),
}))

jest.mock('@/components/layout/Header', () => ({
  Header: ({ theme, onThemeChange, onLogout }: { theme: string; onThemeChange: (t: string) => void; onLogout: () => void }) => (
    <div data-testid="header">
      <span data-testid="theme">{theme}</span>
      <button onClick={() => onThemeChange(theme === 'dark' ? 'light' : 'dark')}>Toggle Theme</button>
      <button onClick={onLogout}>Logout</button>
    </div>
  ),
}))

// Mock page components
jest.mock('@/components/pages/Dashboard', () => ({
  Dashboard: () => <div data-testid="dashboard">Dashboard Page</div>,
}))

jest.mock('@/components/pages/Targets', () => ({
  Targets: () => <div data-testid="targets">Targets Page</div>,
}))

jest.mock('@/components/pages/Scans', () => ({
  Scans: () => <div data-testid="scans">Scans Page</div>,
}))

jest.mock('@/components/pages/Findings', () => ({
  Findings: () => <div data-testid="findings">Findings Page</div>,
}))

jest.mock('@/components/pages/Compliance', () => ({
  Compliance: () => <div data-testid="compliance">Compliance Page</div>,
}))

jest.mock('@/components/pages/Reports', () => ({
  Reports: () => <div data-testid="reports">Reports Page</div>,
}))

jest.mock('@/components/pages/Settings', () => ({
  Settings: () => <div data-testid="settings">Settings Page</div>,
}))

jest.mock('@/components/pages/LoginPage', () => ({
  LoginPage: ({ onRegister, onForgotPassword }: { onRegister: () => void; onForgotPassword: () => void }) => (
    <div data-testid="login-page">
      <button onClick={onRegister}>Register</button>
      <button onClick={onForgotPassword}>Forgot Password</button>
    </div>
  ),
}))

jest.mock('@/components/pages/RegisterPage', () => ({
  RegisterPage: ({ onBackToLogin }: { onBackToLogin: () => void }) => (
    <div data-testid="register-page">
      <button onClick={onBackToLogin}>Back to Login</button>
    </div>
  ),
}))

jest.mock('@/components/pages/PasswordResetPage', () => ({
  PasswordResetPage: ({ onBackToLogin }: { onBackToLogin: () => void }) => (
    <div data-testid="password-reset-page">
      <button onClick={onBackToLogin}>Back to Login</button>
    </div>
  ),
}))

const useSessionMock = jest.requireMock('next-auth/react').useSession

describe('Home', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Loading state', () => {
    it('should show loading spinner when session is loading', () => {
      useSessionMock.mockReturnValue({
        data: null,
        status: 'loading',
      })

      render(<Home />)

      expect(screen.getByText('Loading...')).toBeInTheDocument()
    })
  })

  describe('Unauthenticated state', () => {
    beforeEach(() => {
      useSessionMock.mockReturnValue({
        data: null,
        status: 'unauthenticated',
      })
    })

    it('should show login page by default', () => {
      render(<Home />)

      expect(screen.getByTestId('login-page')).toBeInTheDocument()
    })

    it('should show register page when clicking register', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Register'))

      expect(screen.getByTestId('register-page')).toBeInTheDocument()
    })

    it('should show password reset page when clicking forgot password', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Forgot Password'))

      expect(screen.getByTestId('password-reset-page')).toBeInTheDocument()
    })

    it('should return to login from register page', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Register'))
      expect(screen.getByTestId('register-page')).toBeInTheDocument()

      fireEvent.click(screen.getByText('Back to Login'))
      expect(screen.getByTestId('login-page')).toBeInTheDocument()
    })

    it('should return to login from password reset page', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Forgot Password'))
      expect(screen.getByTestId('password-reset-page')).toBeInTheDocument()

      fireEvent.click(screen.getByText('Back to Login'))
      expect(screen.getByTestId('login-page')).toBeInTheDocument()
    })
  })

  describe('Authenticated state', () => {
    beforeEach(() => {
      useSessionMock.mockReturnValue({
        data: {
          user: {
            name: 'Test User',
            email: 'test@example.com',
          },
          accessToken: 'test-token',
        },
        status: 'authenticated',
      })
    })

    it('should show dashboard by default', () => {
      render(<Home />)

      expect(screen.getByTestId('sidebar')).toBeInTheDocument()
      expect(screen.getByTestId('header')).toBeInTheDocument()
      expect(screen.getByTestId('dashboard')).toBeInTheDocument()
    })

    it('should navigate to targets page', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Targets'))

      expect(screen.getByTestId('targets')).toBeInTheDocument()
    })

    it('should navigate to scans page', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Scans'))

      expect(screen.getByTestId('scans')).toBeInTheDocument()
    })

    it('should navigate to findings page', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Findings'))

      expect(screen.getByTestId('findings')).toBeInTheDocument()
    })

    it('should toggle theme', () => {
      render(<Home />)

      expect(screen.getByTestId('theme')).toHaveTextContent('dark')

      fireEvent.click(screen.getByText('Toggle Theme'))

      expect(screen.getByTestId('theme')).toHaveTextContent('light')
    })

    it('should call signOut when logout is clicked', () => {
      render(<Home />)

      fireEvent.click(screen.getByText('Logout'))

      expect(mockSignOut).toHaveBeenCalled()
    })
  })
})