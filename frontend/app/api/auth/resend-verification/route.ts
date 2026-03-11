import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    console.log('[Resend Verification] Requesting new verification email for:', body.email)
    
    const res = await fetch(`${apiUrl}/auth/resend-verification`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    console.log('[Resend Verification] Response status:', res.status)

    let data
    try {
      data = await res.json()
    } catch (e) {
      console.error('[Resend Verification] Failed to parse response as JSON')
      data = { detail: 'Invalid response from server' }
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('[Resend Verification] Error:', error)
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    
    return NextResponse.json(
      { detail: `Unable to connect to the service. Error: ${errorMessage}` },
      { status: 503 }
    )
  }
}