/**
 * VulnScope - Reports Download API Route Tests
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
    url: options.url || 'http://localhost:3000/api/reports/123/download',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Reports Download API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/reports/[id]/download', () => {
    it('should download a PDF report successfully', async () => {
      const mockBlob = new Blob(['PDF content'], { type: 'application/pdf' })
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 
          'content-type': 'application/pdf',
          'content-disposition': 'attachment; filename="report-123.pdf"'
        }),
        blob: jest.fn().mockResolvedValue(mockBlob)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should download a JSON report successfully', async () => {
      const mockBlob = new Blob(['{"data": "test"}'], { type: 'application/json' })
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 
          'content-type': 'application/json',
          'content-disposition': 'attachment; filename="report-456.json"'
        }),
        blob: jest.fn().mockResolvedValue(mockBlob)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '456' } })

      expect(response.status).toBe(200)
    })

    it('should handle report not found', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 404,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Report not found' })
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '999' } })

      expect(response.status).toBe(404)
    })

    it('should handle non-JSON error response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Internal Server Error</html>')
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

    it('should use default content type if not provided', async () => {
      const mockBlob = new Blob(['content'], { type: '' })
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({}),
        blob: jest.fn().mockResolvedValue(mockBlob)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })

    it('should use default filename if content-disposition not provided', async () => {
      const mockBlob = new Blob(['content'], { type: 'application/pdf' })
      
      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 200,
        headers: new Headers({ 'content-type': 'application/pdf' }),
        blob: jest.fn().mockResolvedValue(mockBlob)
      })

      const request = createMockRequest()
      const response = await GET(request, { params: { id: '123' } })

      expect(response.status).toBe(200)
    })
  })
})