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

