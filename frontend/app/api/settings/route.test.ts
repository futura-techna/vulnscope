/**
 * VulnScope - Settings API Route Tests
 */

import { GET, PUT } from './route'

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
    url: options.url || 'http://localhost:3000/api/settings',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Settings API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/settings', () => {
    it('should fetch settings successfully', async () => {
      const mockSettings = {
        max_concurrent_requests: 50,
        request_timeout: 30,
        enable_crawler: true,
        enable_fuzzer: true,
        rate_limit_per_second: 100
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockSettings)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should handle empty settings', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({})
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

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(503)
    })
  })

  describe('PUT /api/settings', () => {
    it('should update settings successfully', async () => {
      const newSettings = {
        max_concurrent_requests: 100,
        request_timeout: 60
      }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(newSettings)
      })

      const request = createMockRequest({ body: newSettings, method: 'PUT' })
      const response = await PUT(request)

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8000/api/v1/settings',
        expect.objectContaining({
          method: 'PUT',
          body: JSON.stringify(newSettings)
        })
      )
      expect(response.status).toBe(200)
    })

    it('should handle validation error', async () => {
      const invalidSettings = {
        max_concurrent_requests: -1
      }

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ 
          detail: 'Validation error',
          errors: [{ field: 'max_concurrent_requests', message: 'Must be positive' }]
        })
      })

      const request = createMockRequest({ body: invalidSettings, method: 'PUT' })
      const response = await PUT(request)

      expect(response.status).toBe(422)
    })

    it('should handle non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('OK')
      })

      const request = createMockRequest({ body: {}, method: 'PUT' })
      const response = await PUT(request)

      expect(response.status).toBe(502)
    })

    it('should handle connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest({ body: {}, method: 'PUT' })
      const response = await PUT(request)

      expect(response.status).toBe(503)
    })

    it('should handle timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({ body: {}, method: 'PUT' })
      const response = await PUT(request)

      expect(response.status).toBe(504)
    })
  })
})