/**
 * VulnScope - Scan Cancel API Route Tests
 */

import { POST } from './route'

jest.mock('@/lib/api-config', () => ({
  getApiUrl: jest.fn(() => 'http://localhost:8000')
}))

const mockFetch = jest.fn()
global.fetch = mockFetch

const createMockRequest = (options: {
  method?: string
  body?: any
  url?: string
} = {}): any => {
  return {
    json: jest.fn().mockResolvedValue(options.body || {}),
    url: options.url || 'http://localhost:3000/api/scans/123/cancel',
    method: options.method || 'POST',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Scan Cancel API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('POST /api/scans/[id]/cancel', () => {
    it('should cancel a running scan successfully', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ id: 123, status: 'cancelled', message: 'Scan cancelled successfully' })
      })

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should handle scan not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Scan not found' })
      })

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '999' } })

      expect(response.status).toBe(404)
    })

    it('should handle already completed scan', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Cannot cancel a completed scan' })
      })

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })

      expect(response.status).toBe(400)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })

      expect(response.status).toBe(502)
    })

    it('should handle connection error and return 503', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })
      
      expect(response.status).toBe(503)
    })

    it('should handle timeout and return 504', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })
      
      expect(response.status).toBe(504)
    })

    it('should handle unexpected error and return 500', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest()
      const response = await POST(request, { params: { id: '123' } })
      
      expect(response.status).toBe(500)
    })
  })
})