import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    console.log('[Resend Verification] Requesting new verification email for:', body.email)
    console.log('[Resend Verification] API URL:', apiUrl)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 30000) // 30 second timeout
    
    try {
      const res = await fetch(`${apiUrl}/auth/resend-verification`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      })

      clearTimeout(timeoutId)

      console.log('[Resend Verification] Response status:', res.status)
      console.log('[Resend Verification] Content-Type:', res.headers.get('content-type'))

      // Check if response is JSON
      const contentType = res.headers.get('content-type')
      if (!contentType || !contentType.includes('application/json')) {
        // Try to get text response for debugging
        const textResponse = await res.text()
        console.error('[Resend Verification] Non-JSON response:', textResponse.substring(0, 500))
        
        // Handle rate limiting
        if (res.status === 429) {
          return NextResponse.json(
            { detail: 'Trop de requêtes. Veuillez patienter quelques instants avant de réessayer.' },
            { status: 429 }
          )
        }
        
        // Handle common HTTP errors
        if (res.status === 502 || res.status === 503 || res.status === 504) {
          return NextResponse.json(
            { message: 'Le service est actuellement indisponible. Veuillez réessayer dans quelques instants.' },
            { status: 200 } // Return 200 with message to avoid blocking user
          )
        }
        
        return NextResponse.json(
          { message: 'Un nouvel email de vérification a été envoyé.' },
          { status: 200 }
        )
      }

      const data = await res.json()

      if (!res.ok) {
        console.error('[Resend Verification] Error response:', data)
        return NextResponse.json(data, { status: res.status })
      }

      console.log('[Resend Verification] Success:', data)
      return NextResponse.json(data)
      
    } catch (fetchError) {
      clearTimeout(timeoutId)
      throw fetchError
    }
  } catch (error) {
    console.error('[Resend Verification] Error:', error)
    
    // Handle specific error types
    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        return NextResponse.json(
          { message: 'La requête a expiré. Le service peut être en cours de démarrage, veuillez réessayer.' },
          { status: 200 }
        )
      }
      
      if (error.message.includes('fetch failed') || error.message.includes('ECONNREFUSED')) {
        return NextResponse.json(
          { message: 'Impossible de se connecter au service. Veuillez réessayer.' },
          { status: 200 }
        )
      }
    }
    
    return NextResponse.json(
      { message: 'Une erreur s\'est produite. Veuillez réessayer.' },
      { status: 200 }
    )
  }
}
