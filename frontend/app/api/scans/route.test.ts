/**
 * VulnScope - Scans API Route Tests
 */

import { GET, POST } from './route'

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
    url: options.url || 'http://localhost:3000/api/scans',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Scans API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/scans', () => {
    it('should fetch scans successfully', async () => {
      const mockScans = [
        { id: '1', name: 'Scan 1', status: 'completed', findings_count: 5 },
        { id: '2', name: 'Scan 2', status: 'running', progress: 50 }
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockScans)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should handle scans with target_id filter', async () => {
      const mockScans = [
        { id: '1', name: 'Scan 1', target_id: 'target-1' }
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockScans)
      })

      const request = createMockRequest({ url: 'http://localhost:3000/api/scans?target_id=target-1' })
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

  describe('POST /api/scans', () => {
    it('should create a scan successfully', async () => {
      const newScan = { 
        target_id: 'target-1', 
        name: 'Test Scan',
        scan_type: 'full'
      }
      const createdScan = { 
        id: 'scan-1', 
        ...newScan, 
        status: 'pending',
        progress: 0 
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(createdScan)
      })

      const request = createMockRequest({ body: newScan, method: 'POST' })
      const response = await POST(request)

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8000/api/v1/scans',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(newScan)
        })
      )
      expect(response.status).toBe(201)
    })

    it('should create a quick scan', async () => {
      const newScan = { 
        target_id: 'target-1', 
        name: 'Quick Scan',
        scan_type: 'quick',
        enable_fuzzer: false
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ id: '1', ...newScan })
      })

      const request = createMockRequest({ body: newScan, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })

    it('should handle validation error', async () => {
      const newScan = { target_id: '', name: '' }

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ 
          detail: 'Validation error',
          errors: [{ field: 'target_id', message: 'Required' }]
        })
      })

      const request = createMockRequest({ body: newScan, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('OK')
      })

      const request = createMockRequest({ body: {}, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({ body: { target_id: '1' }, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should handle generic error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest({ body: { target_id: '1' }, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(500)
    })
  })
})