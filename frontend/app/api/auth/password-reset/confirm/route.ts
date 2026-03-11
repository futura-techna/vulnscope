import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    console.log('[Password Reset Confirm] Confirming reset')
    console.log('[Password Reset Confirm] API URL:', apiUrl)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 30000)
    
    try {
      const res = await fetch(`${apiUrl}/auth/password-reset/confirm`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      console.log('[Password Reset Confirm] Response status:', res.status)
      console.log('[Password Reset Confirm] Content-Type:', res.headers.get('content-type'))

      // Check if response is JSON
      const contentType = res.headers.get('content-type')
      if (!contentType || !contentType.includes('application/json')) {
        const textResponse = await res.text()
        console.error('[Password Reset Confirm] Non-JSON response:', textResponse.substring(0, 500))
        
        // Handle rate limiting
        if (res.status === 429) {
          return NextResponse.json(
            { detail: 'Trop de requêtes. Veuillez patienter quelques instants avant de réessayer.' },
            { status: 429 }
          )
        }
        
        // Handle server errors
        if (res.status === 502 || res.status === 503 || res.status === 504) {
          return NextResponse.json(
            { detail: 'Le service est actuellement indisponible. Veuillez réessayer dans quelques instants.' },
            { status: res.status }
          )
        }
        
        return NextResponse.json(
          { detail: 'Erreur de communication avec le serveur. Veuillez réessayer.' },
          { status: 502 }
        )
      }

      const data = await res.json()

      if (!res.ok) {
        console.error('[Password Reset Confirm] Error response:', data)
        return NextResponse.json(data, { status: res.status })
      }

      console.log('[Password Reset Confirm] Success')
      return NextResponse.json(data)
      
    } catch (fetchError) {
      clearTimeout(timeoutId)
      throw fetchError
    }
  } catch (error) {
    console.error('[Password Reset Confirm] Confirmation error:', error)
    
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return NextResponse.json(
          { detail: 'La requête a expiré. Le service peut être en cours de démarrage, veuillez réessayer.' },
          { status: 504 }
        )
      }
      
      if (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED')) {
        return NextResponse.json(
          { detail: 'Impossible de se connecter au service. Veuillez réessayer.' },
          { status: 503 }
        )
      }
    }
    
    return NextResponse.json(
      { detail: 'Une erreur inattendue s\'est produite. Veuillez réessayer.' },
      { status: 500 }
    )
  }
}
