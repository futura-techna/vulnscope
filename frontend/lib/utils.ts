import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { format, formatDistanceToNow, parseISO, isValid } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatDate(date: string | Date, formatStr: string = 'PPP'): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) {
      return 'Invalid date'
    }
    return format(dateObj, formatStr)
  } catch {
    return 'Invalid date'
  }
}

export function formatRelativeDate(date: string | Date): string {
  try {
    const dateObj = typeof date === 'string' ? parseISO(date) : date
    if (!isValid(dateObj)) {
      return 'Invalid date'
    }
    return formatDistanceToNow(dateObj, { addSuffix: true })
  } catch {
    return 'Invalid date'
  }
}

export function getSeverityColor(severity: string): string {
  const severityColors: Record<string, string> = {
    critical: 'text-red-600 bg-red-50',
    high: 'text-orange-600 bg-orange-50',
    medium: 'text-yellow-600 bg-yellow-50',
    low: 'text-blue-600 bg-blue-50',
    info: 'text-gray-600 bg-gray-50',
  }
  return severityColors[severity.toLowerCase()] || severityColors.info
}

export function getSeverityTextColor(severity: string): string {
  const severityTextColors: Record<string, string> = {
    critical: 'text-red-600',
    high: 'text-orange-600',
    medium: 'text-yellow-600',
    low: 'text-blue-600',
    info: 'text-gray-600',
  }
  return severityTextColors[severity.toLowerCase()] || severityTextColors.info
}

export function getStatusColor(status: string): string {
  const statusColors: Record<string, string> = {
    completed: 'text-green-600 bg-green-50',
    running: 'text-blue-600 bg-blue-50',
    pending: 'text-yellow-600 bg-yellow-50',
    failed: 'text-red-600 bg-red-50',
    cancelled: 'text-gray-600 bg-gray-50',
  }
  return statusColors[status.toLowerCase()] || statusColors.pending
}

export function truncate(str: string, length: number): string {
  if (str.length <= length) return str
  return str.slice(0, length) + '...'
}
