/**
 * VulnScope - Resend Verification API Route Tests
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
    url: options.url || 'http://localhost:3000/api/auth/resend-verification',
    method: options.method || 'POST',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Resend Verification API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('POST /api/auth/resend-verification', () => {
    it('should resend verification email successfully', async () => {
      const mockResponse = {
        message: 'Verification email sent successfully'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      expect(response.status).toBe(200)
    })

    it('should handle non-existent email gracefully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({
          message: 'If an account exists, a verification email has been sent'
        })
      })

      const request = createMockRequest({
        body: { email: 'nonexistent@example.com' }
      })
      const response = await POST(request)

      expect(response.status).toBe(200)
    })

    it('should handle rate limiting', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Rate Limited</html>')
      })

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      expect(response.status).toBe(429)
    })

    it('should handle server errors gracefully (503)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Service Unavailable</html>')
      })

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      // Route returns 200 with message to avoid blocking user
      expect(response.status).toBe(200)
    })

    it('should handle bad gateway (502)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 502,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Bad Gateway</html>')
      })

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      // Route returns 200 with message to avoid blocking user
      expect(response.status).toBe(200)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('OK')
      })

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      expect(response.status).toBe(200)
    })

    it('should handle connection error gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      // Route returns 200 with message to avoid blocking user
      expect(response.status).toBe(200)
    })

    it('should handle timeout gracefully', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      // Route returns 200 with message to avoid blocking user
      expect(response.status).toBe(200)
    })

    it('should handle unexpected error gracefully', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({
        body: { email: 'user@example.com' }
      })
      const response = await POST(request)

      // Route returns 200 with message to avoid blocking user
      expect(response.status).toBe(200)
    })

    it('should handle validation error from backend', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Invalid email format' })
      })

      const request = createMockRequest({
        body: { email: 'invalid-email' }
      })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })
  })
})