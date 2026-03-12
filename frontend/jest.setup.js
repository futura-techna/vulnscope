// Learn more: https://github.com/testing-library/jest-dom
import '@testing-library/jest-dom'

// Polyfill for fetch, Request, Response, Headers, AbortController
// Required for testing Next.js API routes
class MockHeaders {
  constructor(init = {}) {
    this._headers = new Map()
    if (init instanceof MockHeaders) {
      init._headers.forEach((value, key) => this._headers.set(key, value))
    } else if (typeof init === 'object' && init !== null) {
      Object.entries(init).forEach(([key, value]) => {
        this._headers.set(key.toLowerCase(), value)
      })
    }
  }
  
  append(name, value) {
    this._headers.set(name.toLowerCase(), value)
  }
  
  delete(name) {
    this._headers.delete(name.toLowerCase())
  }
  
  get(name) {
    return this._headers.get(name.toLowerCase()) || null
  }
  
  has(name) {
    return this._headers.has(name.toLowerCase())
  }
  
  set(name, value) {
    this._headers.set(name.toLowerCase(), value)
  }
  
  forEach(callback) {
    this._headers.forEach((value, key) => callback(value, key, this))
  }
  
  entries() {
    return this._headers.entries()
  }
  
  keys() {
    return this._headers.keys()
  }
  
  values() {
    return this._headers.values()
  }
}

class MockResponse {
  constructor(body, init = {}) {
    this.status = init.status || 200
    this.statusText = init.statusText || ''
    this.ok = this.status >= 200 && this.status < 300
    this._body = body
    this.headers = new MockHeaders(init.headers)
    this.type = 'default'
    this.redirected = false
    this.url = ''
  }
  
  json() {
    return Promise.resolve(typeof this._body === 'string' ? JSON.parse(this._body) : this._body)
  }
  
  text() {
    return Promise.resolve(typeof this._body === 'string' ? this._body : JSON.stringify(this._body))
  }
  
  blob() {
    return Promise.resolve(new Blob([this._body]))
  }
  
  arrayBuffer() {
    return Promise.resolve(new TextEncoder().encode(this._body).buffer)
  }
  
  clone() {
    return new MockResponse(this._body, {
      status: this.status,
      statusText: this.statusText,
      headers: this.headers
    })
  }
  
  static json(data, init = {}) {
    return new MockResponse(JSON.stringify(data), {
      ...init,
      headers: {
        'content-type': 'application/json',
        ...init.headers
      }
    })
  }
  
  static redirect(url, status = 302) {
    const response = new MockResponse(null, { status, headers: { Location: url } })
    response.redirected = true
    return response
  }
  
  static error() {
    const response = new MockResponse(null, { status: 0 })
    response.type = 'error'
    return response
  }
}

class MockRequest {
  constructor(input, init = {}) {
    const urlString = typeof input === 'string' ? input : (input?.url || 'http://localhost:3000')
    Object.defineProperty(this, 'url', {
      value: urlString,
      writable: false,
      enumerable: true,
      configurable: true
    })
    Object.defineProperty(this, 'method', {
      value: init.method || 'GET',
      writable: false,
      enumerable: true,
      configurable: true
    })
    this._headers = new MockHeaders(init.headers)
    this.headers = this._headers
    this._body = init.body
    this.mode = init.mode || 'cors'
    this.credentials = init.credentials || 'same-origin'
    this.cache = init.cache || 'default'
    this.redirect = init.redirect || 'follow'
    this.referrer = init.referrer || ''
    this.integrity = init.integrity || ''
    this.signal = init.signal || null
  }
  
  json() {
    return Promise.resolve(typeof this._body === 'string' ? JSON.parse(this._body) : this._body)
  }
  
  text() {
    return Promise.resolve(typeof this._body === 'string' ? this._body : JSON.stringify(this._body))
  }
  
  blob() {
    return Promise.resolve(new Blob([this._body]))
  }
  
  arrayBuffer() {
    return Promise.resolve(new TextEncoder().encode(this._body).buffer)
  }
  
  formData() {
    return Promise.resolve(new FormData())
  }
  
  clone() {
    return new MockRequest(this.url, {
      method: this.method,
      headers: this.headers,
      body: this._body
    })
  }
}

class MockAbortController {
  constructor() {
    this.signal = { aborted: false, reason: null }
  }
  
  abort(reason) {
    this.signal.aborted = true
    this.signal.reason = reason
  }
}

// Mock fetch that can be overridden in tests
const mockFetch = jest.fn(() => Promise.resolve(new MockResponse('{}', { status: 200 })))

// Set globals
if (typeof globalThis.fetch === 'undefined') {
  globalThis.fetch = mockFetch
  globalThis.Request = MockRequest
  globalThis.Response = MockResponse
  globalThis.Headers = MockHeaders
  globalThis.AbortController = MockAbortController
}

// Mock Next.js server components globally
jest.mock('next/server', () => {
  // Create a proper NextRequest mock that works with URL and body
  class MockNextRequest {
    constructor(input, init = {}) {
      // Handle URL object or string
      const urlString = typeof input === 'string' ? input : (input?.url || 'http://localhost:3000')
      const urlObj = typeof urlString === 'string' ? new URL(urlString) : urlString
      
      // Use Object.defineProperty for read-only properties
      Object.defineProperty(this, 'url', {
        value: urlObj.toString(),
        writable: false,
        enumerable: true,
        configurable: true
      })
      
      Object.defineProperty(this, 'method', {
        value: init.method || 'GET',
        writable: false,
        enumerable: true,
        configurable: true
      })
      
      this._body = init.body
      this._headers = new MockHeaders(init.headers)
      
      // Make headers look like a Map for compatibility
      this.headers = {
        get: (name) => this._headers.get(name),
        set: (name, value) => this._headers.set(name, value),
        has: (name) => this._headers.has(name),
        delete: (name) => this._headers.delete(name),
        append: (name, value) => this._headers.append(name, value),
        entries: () => this._headers.entries(),
        forEach: (cb) => this._headers.forEach(cb),
        keys: () => this._headers.keys(),
        values: () => this._headers.values()
      }
      
      // Add nextUrl property for Next.js compatibility
      this.nextUrl = urlObj
    }
    
    json() {
      try {
        return Promise.resolve(typeof this._body === 'string' ? JSON.parse(this._body) : this._body)
      } catch {
        return Promise.resolve({})
      }
    }
    
    text() {
      return Promise.resolve(typeof this._body === 'string' ? this._body : JSON.stringify(this._body || ''))
    }
    
    blob() {
      return Promise.resolve(new Blob([this._body || '']))
    }
    
    arrayBuffer() {
      return Promise.resolve(new TextEncoder().encode(this._body || '').buffer)
    }
    
    formData() {
      return Promise.resolve(new FormData())
    }
    
    clone() {
      return new MockNextRequest(this.url, {
        method: this.method,
        body: this._body,
        headers: this._headers
      })
    }
  }
  
  // NextResponse mock
  const MockNextResponse = {
    json: (data, init = {}) => ({
      status: init?.status || 200,
      json: async () => data,
      text: async () => JSON.stringify(data),
      headers: new MockHeaders(init?.headers),
      ok: (init?.status || 200) >= 200 && (init?.status || 200) < 300
    }),
    redirect: (url, status = 302) => ({
      status,
      headers: new MockHeaders({ Location: url }),
      json: async () => ({ redirect: url }),
      text: async () => JSON.stringify({ redirect: url }),
      ok: false
    }),
    error: (message = 'Internal Server Error', status = 500) => ({
      status,
      json: async () => ({ error: message }),
      text: async () => message,
      headers: new MockHeaders(),
      ok: false
    })
  }
  
  return {
    NextRequest: MockNextRequest,
    NextResponse: MockNextResponse
  }
})
