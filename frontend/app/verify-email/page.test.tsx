import { render, screen, fireEvent, waitFor, act } from '@testing-library/react'
import VerifyEmailPage from './page'

// Mock next/navigation
const mockPush = jest.fn()
const mockGet = jest.fn()
jest.mock('next/navigation', () => ({
  useSearchParams: () => ({
    get: () => mockGet(),
  }),
  useRouter: () => ({
    push: mockPush,
  }),
}))

// Mock fetch
const mockFetch = jest.fn()
global.fetch = mockFetch

// Helper to create a proper mock response
const createMockResponse = (options: { ok: boolean; status?: number; data: any }) => ({
  ok: options.ok,
  status: options.status || (options.ok ? 200 : 400),
  json: () => Promise.resolve(options.data),
})

describe('VerifyEmailPage', () => {
  beforeEach(() => {
    mockFetch.mockReset()
    mockPush.mockReset()
    mockGet.mockReset()
    mockGet.mockReturnValue('test-token')
    // Mock window.location
    Object.defineProperty(window, 'location', {
      value: { href: '' },
      writable: true,
      configurable: true,
    })
  })

  afterEach(() => {
    jest.useRealTimers()
  })

  describe('Missing token', () => {
    it('should show error when token is missing', async () => {
      mockGet.mockReturnValue(null)
      mockFetch.mockResolvedValue(createMockResponse({ ok: true, data: { message: 'Success' } }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })
      expect(screen.getByText(/Token de vérification manquant/)).toBeInTheDocument()
    })
  })

  describe('Successful verification', () => {
    it('should show success message on successful verification', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: true, 
        data: { message: 'Email verified successfully' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Email vérifié!')).toBeInTheDocument()
      })
      expect(screen.getByText(/Votre email a été vérifié avec succès/)).toBeInTheDocument()
    })
  })

  describe('Error handling', () => {
    it('should show error message on verification failure', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 400, 
        data: { detail: 'Invalid token' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })
      expect(screen.getByText('Invalid token')).toBeInTheDocument()
    })

    it('should handle rate limiting', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 429, 
        data: { detail: 'Trop de requêtes. Veuillez patienter.' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })
      
      await waitFor(() => {
        expect(screen.getByText(/Trop de requêtes/)).toBeInTheDocument()
      })
    })
  })

  describe('Retry functionality', () => {
    it('should show retry button for service unavailable errors', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 500, 
        data: { detail: 'Service indisponible' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })

      const retryButton = await screen.findByText(/Réessayer la vérification/)
      expect(retryButton).toBeInTheDocument()
    })

    it('should show retry button for expired token', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 400, 
        data: { detail: 'Token expiré' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })

      const retryButton = await screen.findByText(/Réessayer la vérification/)
      expect(retryButton).toBeInTheDocument()
    })

    it('should retry verification when retry button clicked', async () => {
      mockFetch
        .mockResolvedValueOnce(createMockResponse({ 
          ok: false, 
          status: 500, 
          data: { detail: 'Service indisponible' } 
        }))
        .mockResolvedValueOnce(createMockResponse({ 
          ok: true, 
          data: { message: 'Success' } 
        }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })

      const retryButton = await screen.findByText(/Réessayer la vérification/)
      
      await act(async () => {
        fireEvent.click(retryButton)
      })

      await waitFor(() => {
        expect(screen.getByText('Email vérifié!')).toBeInTheDocument()
      })
    })
  })

  describe('Resend verification', () => {
    it('should have resend verification form', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 400, 
        data: { detail: 'Token expired' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })

      expect(screen.getByPlaceholderText('Votre adresse email')).toBeInTheDocument()
      const resendButton = await screen.findByRole('button', { name: /Renvoyer/i })
      expect(resendButton).toBeInTheDocument()
    })

    it('should handle resend verification input', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 400, 
        data: { detail: 'Token expired' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Erreur de vérification')).toBeInTheDocument()
      })

      const emailInput = screen.getByPlaceholderText('Votre adresse email')
      fireEvent.change(emailInput, { target: { value: 'test@example.com' } })

      expect(emailInput).toHaveValue('test@example.com')
    })

  })

  describe('UI elements', () => {
    it('should render VulnScope logo', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: true, 
        data: { message: 'Success' } 
      }))

      render(<VerifyEmailPage />)

      expect(screen.getByText('VulnScope')).toBeInTheDocument()
    })

    it('should render support link', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: true, 
        data: { message: 'Success' } 
      }))

      render(<VerifyEmailPage />)

      expect(screen.getByText('Contactez le support')).toBeInTheDocument()
    })

    it('should render return to registration link on error', async () => {
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: false, 
        status: 400, 
        data: { detail: 'Error' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Retour à l\'inscription')).toBeInTheDocument()
      })
    })
  })

  describe('Redirect after success', () => {
    it('should redirect to login after successful verification', async () => {
      jest.useFakeTimers()
      
      mockFetch.mockResolvedValue(createMockResponse({ 
        ok: true, 
        data: { message: 'Success' } 
      }))

      render(<VerifyEmailPage />)

      await waitFor(() => {
        expect(screen.getByText('Email vérifié!')).toBeInTheDocument()
      })

      jest.advanceTimersByTime(3000)

      expect(mockPush).toHaveBeenCalledWith('/?auth=login')
      
      jest.useRealTimers()
    })
  })
})