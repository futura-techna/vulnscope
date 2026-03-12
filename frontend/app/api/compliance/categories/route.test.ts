/**
 * VulnScope - Compliance Categories API Route Tests
 */

import { GET } from './route'

jest.mock('@/lib/api-config', () => ({
  getApiUrl: jest.fn(() => 'http://localhost:8000')
}))

const mockFetch = jest.fn()
global.fetch = mockFetch

const createMockRequest = (options: {
  method?: string
  url?: string
} = {}): any => {
  return {
    json: jest.fn().mockResolvedValue({}),
    url: options.url || 'http://localhost:3000/api/compliance/categories',
    method: options.method || 'GET',
    nextUrl: {
      searchParams: new URLSearchParams(options.url?.split('?')[1] || '')
    }
  }
}

describe('Compliance Categories API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/compliance/categories', () => {
    it('should fetch compliance categories successfully', async () => {
      const mockCategories = [
        { id: '1', name: 'Injection', description: 'SQL, NoSQL, OS injection' },
        { id: '2', name: 'Broken Authentication', description: 'Authentication flaws' },
        { id: '3', name: 'Sensitive Data Exposure', description: 'Data protection issues' }
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockCategories)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should handle empty categories', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue([])
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(200)
    })

    it('should return default data on error response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 500,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Internal server error' })
      })

      const request = createMockRequest()
      const response = await GET(request)

      // Route returns default data with status 200 instead of error
      expect(response.status).toBe(200)
    })

    it('should return default data on non-JSON response', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/html' }),
        text: jest.fn().mockResolvedValue('<html>Error</html>')
      })

      const request = createMockRequest()
      const response = await GET(request)

      // Route returns default data with status 200 instead of error
      expect(response.status).toBe(200)
    })

    it('should return default data on timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest()
      const response = await GET(request)

      // Route returns default data with status 200 instead of error
      expect(response.status).toBe(200)
    })

    it('should return default data on connection error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('fetch failed ECONNREFUSED'))

      const request = createMockRequest()
      const response = await GET(request)

      // Route returns default data with status 200 instead of error
      expect(response.status).toBe(200)
    })

    it('should return default data on generic error', async () => {
      mockFetch.mockRejectedValueOnce(new Error('Unknown error'))

      const request = createMockRequest()
      const response = await GET(request)

      // Route returns default data with status 200 instead of error
      expect(response.status).toBe(200)
    })
  })
})