/**
 * VulnScope - Target by ID API Route Tests
 */

import { GET, DELETE } from './route'

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
    url: options.url || 'http://localhost:3000/api/targets/123',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Target by ID API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/targets/[id]', () => {
    it('should fetch a target by ID successfully', async () => {
      const mockTarget = {
        id: 123,
        name: 'Test Application',
        url: 'https://example.com',
        description: 'Main application',
        created_at: '2024-01-01T00:00:00Z',
        last_scan_at: '2024-01-15T00:00:00Z'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockTarget)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should handle target not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Target not found' })
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '999' } })

      expect(response.status).toBe(404)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(503)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(504)
    })

    it('should handle unexpected error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(500)
    })
  })

  describe('DELETE /api/targets/[id]', () => {
    it('should delete a target successfully', async () => {
      const mockResponse = {
        id: 123,
        message: 'Target deleted successfully'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should handle target not found on delete', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Target not found' })
      })

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '999' } })

      expect(response.status).toBe(404)
    })

    it('should handle target with active scans', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Cannot delete target with active scans' })
      })

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(400)
    })

    it('should handle non-JSON response on delete', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('Error')
      })

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(502)
    })

    it('should handle connection error on delete', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(503)
    })

    it('should handle timeout on delete', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(504)
    })

    it('should handle unexpected error on delete', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({ method: 'DELETE' })
      const response = await DELETE(request, { params: { id: '123' } })

      expect(response.status).toBe(500)
    })
  })
})