/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  output: 'standalone',
  swcMinify: true,
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  env: {
    API_URL: process.env.API_URL || 'http://localhost:8000',
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1',
  },
  async rewrites() {
    const apiUrl = process.env.API_URL || 'http://localhost:8000'
    return [
      // Proxy API requests to backend
      // Note: /api/auth/* routes are handled by NextAuth locally (app/api/auth/[...nextauth])
      // and are NOT rewritten because Next.js file-based API routes take precedence
      {
        source: '/api/v:version/:path*',  // Match /api/v1/* pattern specifically
        destination: `${apiUrl}/api/v:version/:path*`,
      },
      {
        source: '/api/targets/:path*',  // Match /api/targets/*
        destination: `${apiUrl}/api/v1/targets/:path*`,
      },
      {
        source: '/api/scans/:path*',  // Match /api/scans/*
        destination: `${apiUrl}/api/v1/scans/:path*`,
      },
      {
        source: '/api/findings/:path*',  // Match /api/findings/*
        destination: `${apiUrl}/api/v1/findings/:path*`,
      },
      {
        source: '/api/reports/:path*',  // Match /api/reports/*
        destination: `${apiUrl}/api/v1/reports/:path*`,
      },
      {
        source: '/api/users/:path*',  // Match /api/users/*
        destination: `${apiUrl}/api/v1/users/:path*`,
      },
    ]
  },
}

module.exports = nextConfig