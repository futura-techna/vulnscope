/**
 * VulnScope - Reports Generate API Route Tests
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
    url: options.url || 'http://localhost:3000/api/reports/generate',
    method: options.method || 'POST',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Reports Generate API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('POST /api/reports/generate', () => {
    it('should generate a report successfully', async () => {
      const mockResponse = {
        id: 1,
        title: 'Security Report',
        format: 'pdf',
        status: 'completed',
        download_url: '/api/reports/1/download',
        created_at: '2024-01-01T00:00:00Z'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { 
          title: 'Security Report',
          format: 'pdf',
          scan_ids: [1, 2, 3]
        }
      })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })

    it('should generate a JSON report', async () => {
      const mockResponse = {
        id: 2,
        title: 'JSON Report',
        format: 'json',
        status: 'completed'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { format: 'json', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })

    it('should generate an HTML report', async () => {
      const mockResponse = {
        id: 3,
        title: 'HTML Report',
        format: 'html',
        status: 'completed'
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockResponse)
      })

      const request = createMockRequest({
        body: { format: 'html', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })

    it('should handle validation error', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Invalid format specified' })
      })

      const request = createMockRequest({
        body: { format: 'invalid', scan_ids: [] }
      })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })

    it('should handle no scan IDs provided', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'At least one scan ID is required' })
      })

      const request = createMockRequest({
        body: { format: 'pdf', scan_ids: [] }
      })
      const response = await POST(request)

      expect(response.status).toBe(400)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest({
        body: { format: 'pdf', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({
        body: { format: 'pdf', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({
        body: { format: 'pdf', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(504)
    })

    it('should handle unexpected error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({
        body: { format: 'pdf', scan_ids: [1] }
      })
      const response = await POST(request)

      expect(response.status).toBe(500)
    })
  })
})