/**
 * VulnScope - Targets API Route Tests
 */

import { GET, POST } from './route'
import { NextResponse } from 'next/server'

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
    url: options.url || 'http://localhost:3000/api/targets',
    method: options.method || 'GET',
  }
}

describe('Targets API Route', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('GET /api/targets', () => {
    it('should fetch targets successfully', async () => {
      const mockTargets = [
        { id: '1', name: 'Target 1', url: 'https://example1.com' },
        { id: '2', name: 'Target 2', url: 'https://example2.com' }
      ]

      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(mockTargets)
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8000/api/v1/targets',
        expect.objectContaining({
          method: 'GET',
          headers: expect.objectContaining({
            'Content-Type': 'application/json',
            'Accept': 'application/json'
          })
        })
      )
      expect(response.status).toBe(200)
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

    it('should handle error response from backend', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 400,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ detail: 'Invalid request' })
      })

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(400)
    })

    it('should handle request timeout', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest()
      const response = await GET(request)

      expect(response.status).toBe(504)
    })

    it('should handle connection refused', async () => {
      const connectionError = new Error('fetch failed ECONNREFUSED')
      mockFetch.mockRejectedValueOnce(connectionError)

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

  describe('POST /api/targets', () => {
    it('should create a target successfully', async () => {
      const newTarget = { name: 'New Target', url: 'https://newtarget.com' }
      const createdTarget = { id: '1', ...newTarget }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(createdTarget)
      })

      const request = createMockRequest({ body: newTarget, method: 'POST' })
      const response = await POST(request)

      expect(mockFetch).toHaveBeenCalledWith(
        'http://localhost:8000/api/v1/targets',
        expect.objectContaining({
          method: 'POST',
          body: JSON.stringify(newTarget),
          headers: expect.objectContaining({
            'Content-Type': 'application/json'
          })
        })
      )
      expect(response.status).toBe(201)
    })

    it('should handle validation error from backend', async () => {
      const newTarget = { name: '', url: 'invalid-url' }

      mockFetch.mockResolvedValueOnce({
        ok: false,
        status: 422,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue({ 
          detail: 'Validation error',
          errors: [{ field: 'url', message: 'Invalid URL' }]
        })
      })

      const request = createMockRequest({ body: newTarget, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(422)
    })

    it('should handle non-JSON response on create', async () => {
      mockFetch.mockResolvedValueOnce({
        ok: true,
        headers: new Headers({ 'content-type': 'text/plain' }),
        text: jest.fn().mockResolvedValue('OK')
      })

      const request = createMockRequest({ body: {}, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(502)
    })

    it('should handle timeout on create', async () => {
      const abortError = new Error('Aborted')
      abortError.name = 'AbortError'
      mockFetch.mockRejectedValueOnce(abortError)

      const request = createMockRequest({ body: { name: 'Test' }, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(504)
    })

    it('should handle connection error on create', async () => {
      const connectionError = new Error('fetch failed ECONNREFUSED')
      mockFetch.mockRejectedValueOnce(connectionError)

      const request = createMockRequest({ body: { name: 'Test' }, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(503)
    })

    it('should create target with authentication config', async () => {
      const newTarget = {
        name: 'Protected Target',
        url: 'https://api.example.com',
        auth_type: 'bearer',
        auth_config: { token: 'test-token' }
      }
      const createdTarget = { id: '1', ...newTarget }

      mockFetch.mockResolvedValueOnce({
        ok: true,
        status: 201,
        headers: new Headers({ 'content-type': 'application/json' }),
        json: jest.fn().mockResolvedValue(createdTarget)
      })

      const request = createMockRequest({ body: newTarget, method: 'POST' })
      const response = await POST(request)

      expect(response.status).toBe(201)
    })
  })
})