/**
 * VulnScope - Test Utilities Tests
 */

import {
  createMockRequest,
  createMockRequestWithParams,
  createMockFetchResponse,
  MockResponse
} from './test-utils'

describe('test-utils', () => {
  describe('createMockRequest', () => {
    it('creates a mock request with default values', () => {
      const request = createMockRequest({})
      
      expect(request.url).toBe('http://localhost:3000/api/test')
      expect(request.method).toBe('GET')
      expect(request.headers).toBeInstanceOf(Map)
      expect(request.nextUrl).toBeInstanceOf(URL)
    })

    it('creates a mock request with custom url', () => {
      const request = createMockRequest({
        url: 'http://example.com/api/custom'
      })
      
      expect(request.url).toBe('http://example.com/api/custom')
      expect(request.nextUrl.href).toBe('http://example.com/api/custom')
    })

    it('creates a mock request with custom method', () => {
      const request = createMockRequest({
        method: 'POST'
      })
      
      expect(request.method).toBe('POST')
    })

    it('creates a mock request with custom headers', () => {
      const request = createMockRequest({
        headers: {
          'Content-Type': 'application/json',
          'Authorization': 'Bearer token123'
        }
      })
      
      expect(request.headers.get('Content-Type')).toBe('application/json')
      expect(request.headers.get('Authorization')).toBe('Bearer token123')
    })

    it('returns parsed JSON body from json() method', async () => {
      const body = { name: 'test', value: 123 }
      const request = createMockRequest({ body })
      
      const result = await request.json()
      
      expect(result).toEqual(body)
    })

    it('parses string body as JSON in json() method', async () => {
      const request = createMockRequest({
        body: '{"name":"test","value":123}'
      })
      
      const result = await request.json()
      
      expect(result).toEqual({ name: 'test', value: 123 })
    })

    it('returns empty object from json() when no body', async () => {
      const request = createMockRequest({})
      
      const result = await request.json()
      
      expect(result).toEqual({})
    })

    it('returns string body from text() method', async () => {
      const request = createMockRequest({
        body: 'raw text body'
      })
      
      const result = await request.text()
      
      expect(result).toBe('raw text body')
    })

    it('stringifies object body in text() method', async () => {
      const body = { name: 'test' }
      const request = createMockRequest({ body })
      
      const result = await request.text()
      
      expect(result).toBe(JSON.stringify(body))
    })

    it('returns empty string from text() when no body', async () => {
      const request = createMockRequest({})
      
      const result = await request.text()
      
      expect(result).toBe('')
    })

    it('creates nextUrl as URL object', () => {
      const request = createMockRequest({
        url: 'http://example.com/api/test?param=value'
      })
      
      expect(request.nextUrl).toBeInstanceOf(URL)
      expect(request.nextUrl.searchParams.get('param')).toBe('value')
    })
  })

  describe('createMockRequestWithParams', () => {
    it('creates a mock request with params', async () => {
      const request = createMockRequestWithParams(
        'http://localhost:3000/api/test/123',
        { id: '123' }
      )
      
      expect(request.url).toBe('http://localhost:3000/api/test/123')
      expect(request.params).toBeInstanceOf(Promise)
      
      const params = await request.params
      expect(params).toEqual({ id: '123' })
    })

    it('creates a mock request with params and custom options', async () => {
      const request = createMockRequestWithParams(
        'http://localhost:3000/api/test/456',
        { id: '456' },
        {
          method: 'DELETE',
          body: { reason: 'test' },
          headers: { 'Authorization': 'Bearer token' }
        }
      )
      
      expect(request.method).toBe('DELETE')
      expect(request.headers.get('Authorization')).toBe('Bearer token')
      
      const body = await request.json()
      expect(body).toEqual({ reason: 'test' })
      
      const params = await request.params
      expect(params).toEqual({ id: '456' })
    })

    it('creates a mock request with multiple params', async () => {
      const request = createMockRequestWithParams(
        'http://localhost:3000/api/users/123/posts/456',
        { userId: '123', postId: '456' }
      )
      
      const params = await request.params
      expect(params).toEqual({ userId: '123', postId: '456' })
    })
  })

  describe('createMockFetchResponse', () => {
    it('creates a mock response with default values', async () => {
      const response = createMockFetchResponse({})
      
      expect(response.status).toBe(200)
      expect(response.ok).toBe(true)
      expect(response.headers).toBeInstanceOf(Map)
    })

    it('creates a mock response with custom status', () => {
      const response = createMockFetchResponse({
        status: 404
      })
      
      expect(response.status).toBe(404)
      expect(response.ok).toBe(false)
    })

    it('creates a mock response with explicit ok flag', () => {
      const response = createMockFetchResponse({
        status: 200,
        ok: false
      })
      
      expect(response.status).toBe(200)
      expect(response.ok).toBe(false)
    })

    it('creates a mock response with data', async () => {
      const response = createMockFetchResponse({
        data: { message: 'Success', id: 123 }
      })
      
      const result = await response.json()
      
      expect(result).toEqual({ message: 'Success', id: 123 })
    })

    it('creates a mock response with string data', async () => {
      const response = createMockFetchResponse({
        data: 'plain text response'
      })
      
      const jsonResult = await response.json()
      const textResult = await response.text()
      
      expect(jsonResult).toBe('plain text response')
      expect(textResult).toBe('plain text response')
    })

    it('creates a mock response with custom headers', () => {
      const response = createMockFetchResponse({
        headers: {
          'X-Custom-Header': 'custom-value',
          'X-Request-Id': 'req-123'
        }
      })
      
      expect(response.headers.get('content-type')).toBe('application/json')
      expect(response.headers.get('X-Custom-Header')).toBe('custom-value')
      expect(response.headers.get('X-Request-Id')).toBe('req-123')
    })

    it('returns JSON stringified data from text()', async () => {
      const response = createMockFetchResponse({
        data: { name: 'test' }
      })
      
      const result = await response.text()
      
      expect(result).toBe('{"name":"test"}')
    })

    it('handles error status codes correctly', () => {
      const errorCodes = [400, 401, 403, 404, 500, 502, 503]
      
      errorCodes.forEach(status => {
        const response = createMockFetchResponse({ status })
        expect(response.ok).toBe(false)
      })
    })

    it('handles success status codes correctly', () => {
      const successCodes = [200, 201, 202, 204, 206]
      
      successCodes.forEach(status => {
        const response = createMockFetchResponse({ status })
        expect(response.ok).toBe(true)
      })
    })
  })
})