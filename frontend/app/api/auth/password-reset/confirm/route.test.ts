/**
 * VulnScope - Password Reset Confirm API Route Tests
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
    url: options.url || 'http://localhost:3000/api/auth/password-reset/confirm',
    method: options.method || 'POST',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Password Reset Confirm API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('POST /api/auth/password-reset/confirm', () => {
    it('should confirm password reset successfully', async () => {
      const mockResponse = {
        message: 'Password has been reset successfully'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { token: 'valid-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(200)
    })

    it('should handle invalid token error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Invalid or expired token' })
      })

      const request = createMockRequest({
        body: { token: 'invalid-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(400)
    })

    it('should handle rate limiting (429)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 429,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Rate Limited</html>')
      })

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
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
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle service unavailable (503)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 503,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Service Unavailable</html>')
      })

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('Internal Server Error')
      })

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(504)
    })

    it('should handle unexpected error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'newpassword123' }
      })
      const response = await POST(request)

      expect(response.status).toBe(500)
    })

    it('should handle validation error (422)', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Password must be at least 8 characters' })
      })

      const request = createMockRequest({
        body: { token: 'some-token', new_password: 'short' }
      })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })
  })
})