import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    console.log('[Register] Attempting registration for:', body.username, body.email)
    console.log('[Register] API URL:', `${apiUrl}/auth/register`)
    
    const res = await fetch(`${apiUrl}/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    console.log('[Register] Response status:', res.status)

    let data
    try {
      data = await res.json()
    } catch (e) {
      console.error('[Register] Failed to parse response as JSON')
      data = { detail: 'Invalid response from server' }
    }

    console.log('[Register] Response data:', data)

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    return NextResponse.json(data, { status: 201 })
  } catch (error) {
    console.error('[Register] Registration error:', error)
    
    // Provide more helpful error message
    const errorMessage = error instanceof Error ? error.message : 'Unknown error'
    
    return NextResponse.json(
      { detail: `Unable to connect to the registration service. Please ensure the backend is running. Error: ${errorMessage}` },
      { status: 503 }
    )
  }
}
