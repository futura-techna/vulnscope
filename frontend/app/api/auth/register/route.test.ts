/**
 * VulnScope - Register API Route Tests
 */

import { POST } from './route'

const mockFetch = jest.fn()
global.fetch = mockFetch

const createMockRequest = (options: {
  method?: string
  body?: any
  url?: string
} = {}): any => {
  return {
    json: jest.fn().mockResolvedValue(options.body || {}),
    url: options.url || 'http://localhost:3000/api/auth/register',
    method: options.method || 'POST',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Register API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully', async () => {
      const mockResponse = {
        id: 1,
        username: 'testuser',
        email: 'test@example.com',
        message: 'User registered successfully. Please check your email to verify your account.'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })

    it('should handle duplicate username error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Username already exists' })
      })

      const request = createMockRequest({
        body: { username: 'existinguser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(400)
    })

    it('should handle duplicate email error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Email already registered' })
      })

      const request = createMockRequest({
        body: { username: 'newuser', email: 'existing@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(400)
    })

    it('should handle validation error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Validation error' })
      })

      const request = createMockRequest({
        body: { username: '', email: 'invalid-email', password: 'short' }
      })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })

    it('should handle rate limiting (429)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Rate Limited</html>')
      })

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(429)
    })

    it('should handle server unavailable (502)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 502,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Bad Gateway</html>')
      })

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(504)
    })

    it('should handle unexpected error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({
        body: { username: 'testuser', email: 'test@example.com', password: 'password123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(500)
    })
  })
})