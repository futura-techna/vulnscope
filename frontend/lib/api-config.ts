/**
 * VulnScope - API Configuration
 * Centralized API URL configuration for frontend
 */

/**
 * Get the backend API URL
 * This function reads environment variables at runtime to ensure
 * they are properly picked up in all environments (local, Docker, Render)
 * 
 * Priority:
 * 1. API_URL - Server-side only, set by Render or docker-compose
 * 2. NEXT_PUBLIC_API_URL - Client-side, but we strip /api/v1 suffix for server-side proxy
 * 3. Default to localhost for development
 */
export function getApiUrl(): string {
  return (
    process.env.API_URL || 
    process.env.NEXT_PUBLIC_API_URL?.replace('/api/v1', '') || 
    'http://localhost:8000'
  )
}

/**
 * Get the frontend API base URL
 * For client-side requests, we always use relative URLs to go through
 * Next.js API routes (which handle the proxy to backend)
 */
export function getFrontendApiBase(): string {
  return '/api'
}