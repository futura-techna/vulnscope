import { NextRequest, NextResponse } from 'next/server'
import { getApiUrl } from '@/lib/api-config'

export async function GET(
  request: NextRequest,
  { params }: { params: { id: string } }
) {
  const apiUrl = getApiUrl()
  const { id } = params
  
  try {
    console.log('[Reports] Downloading report:', id)
    
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 60000)
    
    const response = await fetch(`${apiUrl}/api/v1/reports/${id}/download`, {
      method: 'GET',
      signal: controller.signal,
    })

    clearTimeout(timeoutId)

    if (!response.ok) {
      const contentType = response.headers.get('content-type')
      if (contentType && contentType.includes('application/json')) {
        const data = await response.json()
        console.error('[Reports Download] Error response:', data)
        return NextResponse.json(data, { status: response.status })
      }
      
      const textResponse = await response.text()
      console.error('[Reports Download] Non-JSON error:', textResponse.substring(0, 500))
      return NextResponse.json(
        { detail: 'Erreur de communication avec le serveur.' },
        { status: 502 }
      )
    }

    // Get the content type from the backend response
    const contentType = response.headers.get('content-type') || 'application/octet-stream'
    
    // Get the file content as a blob
    const blob = await response.blob()
    
    // Return the file with appropriate headers
    return new NextResponse(blob, {
      status: 200,
      headers: {
        'Content-Type': contentType,
        'Content-Disposition': response.headers.get('Content-Disposition') || `attachment; filename="report-${id}"`,
      },
    })
  } catch (error) {
    console.error('[Reports Download] Error downloading report:', error)
    
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
