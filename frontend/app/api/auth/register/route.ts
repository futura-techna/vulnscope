import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  const apiUrl = process.env.API_URL || 'http://localhost:8000'
  
  try {
    const body = await request.json()
    
    const res = await fetch(`${apiUrl}/auth/register`, {
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

    return NextResponse.json(data, { status: 201 })
  } catch (error) {
    console.error('Registration error:', error)
    return NextResponse.json(
      { detail: 'An error occurred during registration' },
      { status: 500 }
    )
  }
}