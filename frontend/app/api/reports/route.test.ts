/**
 * VulnScope - Reports API Route Tests
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
    url: options.url || 'http://localhost:3000/api/reports',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Reports API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/reports', () => {
    it('should fetch reports successfully', async () => {
      const mockReports = [
        { id: '1', name: 'Security Report Q1', format: 'pdf', created_at: '2024-01-15' },
        { id: '2', name: 'Vulnerability Report', format: 'json', created_at: '2024-01-20' }
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockReports)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should handle empty reports', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue([])
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should handle error response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Internal server error' })
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(500)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(502)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(504)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(503)
    })
  })
})