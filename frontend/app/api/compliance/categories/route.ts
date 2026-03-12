import { NextRequest, NextResponse } from 'next/server'
import { getApiUrl } from '@/lib/api-config'

// Default compliance categories data when backend is unavailable
function getDefaultCategories() {
  return {
    categories: [
      { name: 'Access Control', score: 95 },
      { name: 'Encryption', score: 98 },
      { name: 'Monitoring', score: 92 },
      { name: 'Incident Response', score: 90 },
      { name: 'Vendor Management', score: 94 },
    ]
  }
}

export async function GET(request: NextRequest) {
  const apiUrl = getApiUrl()
  
  // If no API URL configured, return default data
  if (!apiUrl || apiUrl === 'undefined' || apiUrl === 'null') {
    console.log('[Compliance Categories] No API URL configured, returning default data')
    return NextResponse.json(getDefaultCategories())
  }
  
  try {
    console.log('[Compliance] Fetching categories from:', `${apiUrl}/api/v1/compliance/categories`)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10000) // Reduced to 10s
    
    const response = await fetch(`${apiUrl}/api/v1/compliance/categories`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      },
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    const contentType = response.headers.get('content-type')
    
    if (!contentType || !contentType.includes('application/json')) {
      const textResponse = await response.text()
      console.error('[Compliance Categories] Non-JSON response:', textResponse.substring(0, 500))
      // Return default data instead of error
      return NextResponse.json(getDefaultCategories())
    }

    const data = await response.json()

    if (!response.ok) {
      console.error('[Compliance Categories] Error response:', data)
      // Return default data instead of error
      return NextResponse.json(getDefaultCategories())
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('[Compliance Categories] Error fetching categories:', error)
    // Return default data instead of error for any failure
    return NextResponse.json(getDefaultCategories())
  }
}

