/**
 * VulnScope - Test Utilities for API Route Testing
 * 
 * This module provides helper functions for creating mock request objects
 * in API route tests without relying on Next.js internals.
 */

/**
 * Creates a mock request object compatible with Next.js API route handlers
 */
export function createMockRequest(options: {
  url?: string
  method?: string
  body?: any
  headers?: Record<string, string>
}): {
  url: string
  method: string
  headers: Map<string, string>
  json: () => Promise<any>
  text: () => Promise<string>
  nextUrl: URL
} {
  const { url = 'http://localhost:3000/api/test', method = 'GET', body, headers = {} } = options
  
  const requestHeaders = new Map(Object.entries(headers))
  
  return {
    url,
    method,
    headers: requestHeaders,
    json: async () => {
      if (typeof body === 'string') {
        return JSON.parse(body)
      }
      return body ?? {}
    },
    text: async () => {
      if (typeof body === 'string') {
        return body
      }
      return body ? JSON.stringify(body) : ''
    },
    nextUrl: new URL(url)
  }
}

/**
 * Creates a mock request with URL parameters for dynamic routes
 */
export function createMockRequestWithParams(
  basePath: string,
  params: Record<string, string>,
  options: {
    method?: string
    body?: any
    headers?: Record<string, string>
  } = {}
) {
  const url = basePath
  
  return {
    ...createMockRequest({ url, ...options }),
    params: Promise.resolve(params)
  }
}

/**
 * Mock response object for testing
 */
export interface MockResponse {
  status: number
  ok: boolean
  json: () => Promise<any>
  text: () => Promise<string>
  headers: Map<string, string>
}

/**
 * Creates a mock fetch response
 */
export function createMockFetchResponse(options: {
  ok?: boolean
  status?: number
  data?: any
  headers?: Record<string, string>
}): MockResponse {
  const { ok, status = 200, data, headers = {} } = options
  
  const responseHeaders = new Map(Object.entries({
    'content-type': 'application/json',
    ...headers
  }))
  
  return {
    status,
    ok: ok ?? (status >= 200 && status < 300),
    json: async () => data,
    text: async () => typeof data === 'string' ? data : JSON.stringify(data),
    headers: responseHeaders
  }
}