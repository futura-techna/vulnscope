import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    const res = await fetch(`${apiUrl}/api/auth/password-reset`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    })

    const data = await res.json()

    if (!res.ok) {
      return NextResponse.json(data, { status: res.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('Password reset request error:', error)
    return NextResponse.json(
      { detail: 'An error occurred during password reset request' },
      { status: 500 }
    )
  }
}