import { getApiUrl, getFrontendApiBase } from './api-config'

describe('api-config', () => {
  const originalEnv = process.env

  beforeEach(() => {
    // Reset process.env for each test
    jest.resetModules()
    process.env = { ...originalEnv }
  })

  afterAll(() => {
    // Restore original process.env
    process.env = originalEnv
  })

  describe('getApiUrl', () => {
    it('should return API_URL when set', () => {
      process.env.API_URL = 'http://api.example.com'
      
      const result = getApiUrl()
      
      expect(result).toBe('http://api.example.com')
    })

    it('should return NEXT_PUBLIC_API_URL without /api/v1 suffix', () => {
      delete process.env.API_URL
      process.env.NEXT_PUBLIC_API_URL = 'http://api.example.com/api/v1'
      
      const result = getApiUrl()
      
      expect(result).toBe('http://api.example.com')
    })

    it('should return NEXT_PUBLIC_API_URL as-is when no /api/v1 suffix', () => {
      delete process.env.API_URL
      process.env.NEXT_PUBLIC_API_URL = 'http://api.example.com'
      
      const result = getApiUrl()
      
      expect(result).toBe('http://api.example.com')
    })

    it('should default to localhost:8000 when no env vars set', () => {
      delete process.env.API_URL
      delete process.env.NEXT_PUBLIC_API_URL
      
      const result = getApiUrl()
      
      expect(result).toBe('http://localhost:8000')
    })

    it('should prioritize API_URL over NEXT_PUBLIC_API_URL', () => {
      process.env.API_URL = 'http://priority.example.com'
      process.env.NEXT_PUBLIC_API_URL = 'http://fallback.example.com/api/v1'
      
      const result = getApiUrl()
      
      expect(result).toBe('http://priority.example.com')
    })

    it('should handle NEXT_PUBLIC_API_URL with multiple /api/v1 occurrences', () => {
      delete process.env.API_URL
      process.env.NEXT_PUBLIC_API_URL = 'http://api.example.com/api/v1/api/v1'
      
      const result = getApiUrl()
      
      // Only replaces first occurrence
      expect(result).toBe('http://api.example.com/api/v1')
    })
  })

  describe('getFrontendApiBase', () => {
    it('should return /api', () => {
      const result = getFrontendApiBase()
      
      expect(result).toBe('/api')
    })
  })
})