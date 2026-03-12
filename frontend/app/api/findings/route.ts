import { NextRequest, NextResponse } from 'next/server'
import { getApiUrl } from '@/lib/api-config'

export async function GET(request: NextRequest) {
  const apiUrl = getApiUrl()
  const { searchParams } = new URL(request.url)
  
  // Build query string from all possible params
  const params = new URLSearchParams()
  const scan_id = searchParams.get('scan_id')
  const target_id = searchParams.get('target_id')
  const severity = searchParams.get('severity')
  const vuln_type = searchParams.get('vuln_type')
  const status = searchParams.get('status')
  const skip = searchParams.get('skip')
  const limit = searchParams.get('limit')
  
  if (scan_id) params.append('scan_id', scan_id)
  if (target_id) params.append('target_id', target_id)
  if (severity) params.append('severity', severity)
  if (vuln_type) params.append('vuln_type', vuln_type)
  if (status) params.append('status', status)
  if (skip) params.append('skip', skip)
  if (limit) params.append('limit', limit)
  
  const queryString = params.toString()
  
  try {
    console.log('[Findings] Fetching findings from:', `${apiUrl}/api/v1/findings${queryString ? `?${queryString}` : ''}`)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 30000)
    
    const response = await fetch(`${apiUrl}/api/v1/findings${queryString ? `?${queryString}` : ''}`, {
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
      console.error('[Findings] Non-JSON response:', textResponse.substring(0, 500))
      return NextResponse.json(
        { detail: 'Erreur de communication avec le serveur.' },
        { status: 502 }
      )
    }

    const data = await response.json()

    if (!response.ok) {
      console.error('[Findings] Error response:', data)
      return NextResponse.json(data, { status: response.status })
    }

    return NextResponse.json(data)
  } catch (error) {
    console.error('[Findings] Error fetching findings:', error)
    
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
