import { NextRequest, NextResponse } from 'next/server'
import { getApiUrl } from '@/lib/api-config'

export async function GET(request: NextRequest) {
  const apiUrl = getApiUrl()
  try {
    console.log('[Compliance] Fetching categories from:', `${apiUrl}/api/v1/compliance/categories`)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 30000)
    
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
      return NextResponse.json(
        { detail: 'Erreur de communication avec le serveur.' },
        { status: 502 }
      )
    }

    const data = await response.json()

    if (!response.ok) {
      console.error('[Compliance Categories] Error response:', data)
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('[Compliance Categories] Error fetching categories:', error)
    
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return NextResponse.json(
          { detail: 'La requête a expiré.' },
          { status: 504 }
        )
      }
      
      if (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED')) {
        return NextResponse.json(
          { detail: 'Impossible de se connecter au serveur backend.' },
          { status: 503 }
        )
      }
    }
    
    return NextResponse.json(
      { detail: 'Une erreur inattendue s\'est produite.' },
      { status: 500 }
    )
  }
}

