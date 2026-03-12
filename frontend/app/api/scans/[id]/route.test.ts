/**
 * VulnScope - Scan by ID API Route Tests
 */

import { GET } from './route'

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
    url: options.url || 'http://localhost:3000/api/scans/123',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Scan by ID API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/scans/[id]', () => {
    it('should fetch a scan by ID successfully', async () => {
      const mockScan = {
        id: 123,
        target_id: 1,
        status: 'completed',
        created_at: '2024-01-01T00:00:00Z',
        findings_count: 5,
        critical_count: 1,
        high_count: 2
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockScan)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should fetch a running scan', async () => {
      const mockScan = {
        id: 456,
        target_id: 2,
        status: 'running',
        progress: 50,
        created_at: '2024-01-01T00:00:00Z'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockScan)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '456' } })

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
})