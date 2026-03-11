import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    console.log('[Verify Email] Verifying token...')
    
    const res = await fetch(`${apiUrl}/auth/verify-email`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    console.log('[Verify Email] Response status:', res.status)

    let data
    try {
      data = await res.json()
    } catch (e) {
      console.error('[Verify Email] Failed to parse response as JSON')
      data = { detail: 'Invalid response from server' }
    }

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('[Verify Email] Verification error:', error)
    
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    
    return NextResponse.json(
      { detail: `Unable to connect to the verification service. Error: ${errorMessage}` },
      { status: 503 }
    )
  }
}