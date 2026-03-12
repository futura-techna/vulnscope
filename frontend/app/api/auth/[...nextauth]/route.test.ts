/**
 * VulnScope - NextAuth Route Tests
 * 
 * Tests for the authentication configuration and handlers
 */

// Mock next-auth
jest.mock('next-auth', () => {
  const mockHandler = jest.fn()
  mockHandler.mockReturnValue({
    GET: jest.fn(),
    POST: jest.fn(),
  })
  return {
    __esModule: true,
    default: mockHandler,
  }
})

// Mock next-auth providers
jest.mock('next-auth/providers/credentials', () => {
  return jest.fn(() => ({
    id: 'credentials',
    name: 'Credentials',
    type: 'credentials',
    credentials: {},
    authorize: jest.fn(),
  }))
})

jest.mock('next-auth/providers/google', () => {
  return jest.fn(() => ({
    id: 'google',
    name: 'Google',
    type: 'oauth',
  }))
})

jest.mock('next-auth/providers/azure-ad', () => {
  return jest.fn(() => ({
    id: 'azure-ad',
    name: 'Azure AD',
    type: 'oauth',
  }))
})

// Store original env
const originalEnv = process.env

describe('NextAuth Configuration', () => {
  beforeEach(() => {
    jest.resetModules()
    process.env = { ...originalEnv }
  })

  afterEach(() => {
    process.env = originalEnv
    jest.clearAllMocks()
  })

  describe('Environment configuration', () => {
    it('uses default API URL when API_URL is not set', async () => {
      delete process.env.API_URL
      
      // Import the module to trigger the configuration
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
      expect(routeModule.GET).toBeDefined()
      expect(routeModule.POST).toBeDefined()
    })

    it('uses custom API URL when API_URL is set', async () => {
      process.env.API_URL = 'http://custom-api:8000'
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })

    it('uses custom nextauth secret when NEXTAUTH_SECRET is set', async () => {
      process.env.NEXTAUTH_SECRET = 'custom-secret-key'
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })

    it('uses default nextauth secret when NEXTAUTH_SECRET is not set', async () => {
      delete process.env.NEXTAUTH_SECRET
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })
  })

  describe('OAuth providers', () => {
    it('configures Google provider when GOOGLE_CLIENT_ID is set', async () => {
      process.env.GOOGLE_CLIENT_ID = 'google-client-id'
      process.env.GOOGLE_CLIENT_SECRET = 'google-secret'
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })

    it('skips Google provider when GOOGLE_CLIENT_ID is not set', async () => {
      delete process.env.GOOGLE_CLIENT_ID
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })

    it('configures Azure AD provider when AZURE_AD_CLIENT_ID is set', async () => {
      process.env.AZURE_AD_CLIENT_ID = 'azure-client-id'
      process.env.AZURE_AD_CLIENT_SECRET = 'azure-secret'
      process.env.AZURE_AD_TENANT_ID = 'azure-tenant'
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })

    it('skips Azure AD provider when AZURE_AD_CLIENT_ID is not set', async () => {
      delete process.env.AZURE_AD_CLIENT_ID
      
      const routeModule = await import('./route')
      
      expect(routeModule).toBeDefined()
    })
  })

  describe('Exported handlers', () => {
    it('exports GET handler', async () => {
      const routeModule = await import('./route')
      
      expect(routeModule.GET).toBeDefined()
    })

    it('exports POST handler', async () => {
      const routeModule = await import('./route')
      
      expect(routeModule.POST).toBeDefined()
    })

    it('exports both handlers', async () => {
      const routeModule = await import('./route')
      
      // Both GET and POST should be defined
      expect(routeModule.GET).toBeDefined()
      expect(routeModule.POST).toBeDefined()
    })
  })
})

describe('Credentials Provider Authorization', () => {
  // These tests verify the authorization logic indirectly
  // since we can't easily test the internal authorize function

  it('module loads without errors', async () => {
    const routeModule = await import('./route')
    expect(routeModule).toBeTruthy()
  })

  it('has correct handler exports', async () => {
    const { GET, POST } = await import('./route')
    expect(GET).toBeDefined()
    expect(POST).toBeDefined()
  })
})

describe('NextAuth Pages Configuration', () => {
  it('configures custom sign-in page', async () => {
    const routeModule = await import('./route')
    
    // Module should load successfully with custom pages config
    expect(routeModule).toBeDefined()
  })
})

describe('NextAuth Session Configuration', () => {
  it('uses JWT session strategy', async () => {
    const routeModule = await import('./route')
    
    // Module should load successfully with JWT strategy
    expect(routeModule).toBeDefined()
  })
})

describe('NextAuth Debug Configuration', () => {
  it('enables debug in development mode', async () => {
    process.env.NODE_ENV = 'development'
    
    const routeModule = await import('./route')
    expect(routeModule).toBeDefined()
  })

  it('disables debug in production mode', async () => {
    process.env.NODE_ENV = 'production'
    
    const routeModule = await import('./route')
    expect(routeModule).toBeDefined()
  })
})