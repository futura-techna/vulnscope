/**
 * VulnScope - Findings API Route Tests
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
    url: options.url || 'http://localhost:3000/api/findings',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Findings API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/findings', () => {
    it('should fetch findings successfully', async () => {
      const mockFindings = {
        total: 2,
        findings: [
          { id: '1', title: 'SQL Injection', severity: 'Critical', status: 'Open' },
          { id: '2', title: 'XSS', severity: 'High', status: 'Open' }
        ]
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockFindings)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should fetch findings with severity filter', async () => {
      const mockFindings = {
        total: 1,
        findings: [
          { id: '1', title: 'SQL Injection', severity: 'Critical' }
        ]
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockFindings)
      })

      const request = createMockRequest({ url: 'http://localhost:3000/api/findings?severity=Critical' })
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should fetch findings with scan_id filter', async () => {
      const mockFindings = {
        total: 1,
        findings: [{ id: '1', scan_id: 'scan-1' }]
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockFindings)
      })

      const request = createMockRequest({ url: 'http://localhost:3000/api/findings?scan_id=scan-1' })
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should fetch findings with pagination', async () => {
      const mockFindings = {
        total: 50,
        findings: Array(10).fill(null).map((_, i) => ({ id: `${i}` }))
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockFindings)
      })

      const request = createMockRequest({ url: 'http://localhost:3000/api/findings?limit=10&offset=10' })
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

    it('should handle generic error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(500)
    })
  })
})