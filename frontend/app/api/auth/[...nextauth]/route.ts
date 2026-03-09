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
          const res = await fetch(`${apiUrl}/api/auth/login`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify({
              username: credentials?.username,
              password: credentials?.password,
            }),
          })

          const user = await res.json()

          if (res.ok && user) {
            return {
              id: user.id || user.user_id || '1',
              name: user.username || credentials?.username,
              email: user.email || `${credentials?.username}@vulnscope.local`,
              accessToken: user.access_token || user.token,
            }
          }
          
          return null
        } catch (error) {
          console.error('Auth error:', error)
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