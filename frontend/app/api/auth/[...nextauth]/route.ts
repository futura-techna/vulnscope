import NextAuth from 'next-auth'
import CredentialsProvider from 'next-auth/providers/credentials'
import GoogleProvider from 'next-auth/providers/google'
import AzureADProvider from 'next-auth/providers/azure-ad'

const handler = NextAuth({
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        username: { label: 'Username', type: 'text', placeholder: 'jsmith' },
        password: { label: 'Password', type: 'password' }
      },
      async authorize(credentials, req) {
        // Connect to the backend API for authentication
        const apiUrl = process.env.API_URL || 'http://localhost:8000'
        
        try {
          console.log('[Auth] Attempting login for:', credentials?.username)
          console.log('[Auth] API URL:', apiUrl)
          
          const controller = new AbortController()
          const timeoutId = setTimeout(() => controller.abort(), 30000)
          
          const res = await fetch(`${apiUrl}/api/auth/login`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
            },
            body: JSON.stringify({
              username: credentials?.username,
              password: credentials?.password,
            }),
            signal: controller.signal,
          })

          clearTimeout(timeoutId)

          console.log('[Auth] Response status:', res.status)
          console.log('[Auth] Content-Type:', res.headers.get('content-type'))

          // Check if response is JSON
          const contentType = res.headers.get('content-type')
          if (!contentType || !contentType.includes('application/json')) {
            const textResponse = await res.text()
            console.error('[Auth] Non-JSON response:', textResponse.substring(0, 500))
            
            // Handle rate limiting
            if (res.status === 429) {
              throw new Error('Trop de requêtes. Veuillez patienter quelques instants avant de réessayer.')
            }
            
            // Handle server errors
            if (res.status === 502 || res.status === 503 || res.status === 504) {
              throw new Error('Le service est actuellement indisponible. Veuillez réessayer dans quelques instants.')
            }
            
            throw new Error('Erreur de communication avec le serveur. Veuillez réessayer.')
          }

          const user = await res.json()

          if (res.ok && user) {
            console.log('[Auth] Login successful for:', credentials?.username)
            return {
              id: user.id || user.user_id || '1',
              name: user.username || credentials?.username,
              email: user.email || `${credentials?.username}@vulnscope.local`,
              accessToken: user.access_token || user.token,
            }
          }
          
          console.log('[Auth] Login failed:', user)
          return null
        } catch (error) {
          console.error('Auth error:', error)
          
          // Re-throw error messages we created
          if (error instanceof Error && error.message.includes('Trop de requêtes')) {
            throw error
          }
          if (error instanceof Error && error.message.includes('indisponible')) {
            throw error
          }
          if (error instanceof Error && error.message.includes('communication')) {
            throw error
          }
          
          // Handle timeout
          if (error instanceof Error && error.name === 'AbortError') {
            throw new Error('La requête a expiré. Le service peut être en cours de démarrage, veuillez réessayer.')
          }
          
          // Handle connection errors
          if (error instanceof Error && (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED'))) {
            throw new Error('Impossible de se connecter au service d\'authentification. Veuillez réessayer.')
          }
          
          return null
        }
      },
    }),
    // Google OAuth - requires GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET env vars
    ...(process.env.GOOGLE_CLIENT_ID ? [
      GoogleProvider({
        clientId: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      })
    ] : []),
    // Azure AD OAuth - requires AZURE_AD_CLIENT_ID and AZURE_AD_CLIENT_SECRET env vars
    ...(process.env.AZURE_AD_CLIENT_ID ? [
      AzureADProvider({
        clientId: process.env.AZURE_AD_CLIENT_ID,
        clientSecret: process.env.AZURE_AD_CLIENT_SECRET || '',
        tenantId: process.env.AZURE_AD_TENANT_ID,
      })
    ] : []),
  ],
  callbacks: {
    async jwt({ token, user, account }) {
      if (user) {
        token.accessToken = user.accessToken
      }
      if (account?.access_token) {
        token.oauthAccessToken = account.access_token
      }
      return token
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string
      return session
    },
  },
  pages: {
    signIn: '/login',
    error: '/login',
  },
  session: {
    strategy: 'jwt',
  },
  secret: process.env.NEXTAUTH_SECRET || 'vulnscope-nextauth-secret-change-in-production',
  debug: process.env.NODE_ENV === 'development',
})

export { handler as GET, handler as POST }