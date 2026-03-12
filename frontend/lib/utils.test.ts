/**
 * VulnScope - Utils Tests
 */

import {
  cn,
  formatDate,
  formatRelativeDate,
  getSeverityColor,
  getSeverityTextColor,
  getStatusColor,
  truncate
} from './utils'

describe('cn (className merger)', () => {
  it('should merge class names', () => {
    const result = cn('class1', 'class2')
    expect(result).toContain('class1')
    expect(result).toContain('class2')
  })

  it('should handle conditional classes', () => {
    const result = cn('base', true && 'included', false && 'excluded')
    expect(result).toContain('base')
    expect(result).toContain('included')
    expect(result).not.toContain('excluded')
  })

  it('should merge tailwind classes', () => {
    const result = cn('px-2 py-1', 'px-4')
    expect(result).toContain('py-1')
    expect(result).toContain('px-4')
  })

  it('should handle undefined values', () => {
    const result = cn('class1', undefined, 'class2')
    expect(result).toContain('class1')
    expect(result).toContain('class2')
  })

  it('should handle empty strings', () => {
    const result = cn('class1', '', 'class2')
    expect(result).toContain('class1')
    expect(result).toContain('class2')
  })

  it('should handle object notation', () => {
    const result = cn({ active: true, disabled: false })
    expect(result).toContain('active')
    expect(result).not.toContain('disabled')
  })

  it('should handle arrays', () => {
    const result = cn(['class1', 'class2'])
    expect(result).toContain('class1')
    expect(result).toContain('class2')
  })

  it('should handle no arguments', () => {
    const result = cn()
    expect(result).toBe('')
  })
})

describe('formatDate', () => {
  it('should format a valid date string', () => {
    const result = formatDate('2024-01-15')
    expect(result).not.toBe('Invalid date')
  })

  it('should format a Date object', () => {
    const date = new Date('2024-01-15')
    const result = formatDate(date)
    expect(result).not.toBe('Invalid date')
  })

  it('should return invalid date for invalid string', () => {
    const result = formatDate('not-a-date')
    expect(result).toBe('Invalid date')
  })

  it('should handle custom format', () => {
    const result = formatDate('2024-01-15', 'yyyy-MM-dd')
    expect(result).toBe('2024-01-15')
  })

  it('should handle ISO date strings', () => {
    const result = formatDate('2024-01-15T10:30:00Z')
    expect(result).not.toBe('Invalid date')
  })

  it('should handle empty string', () => {
    const result = formatDate('')
    expect(result).toBe('Invalid date')
  })

  it('should handle null gracefully', () => {
    const result = formatDate(null as unknown as string)
    expect(result).toBe('Invalid date')
  })
})

describe('formatRelativeDate', () => {
  it('should format relative date', () => {
    const date = new Date()
    date.setDate(date.getDate() - 1)
    const result = formatRelativeDate(date.toISOString())
    expect(result).toContain('ago')
  })

  it('should handle date object', () => {
    const date = new Date()
    date.setHours(date.getHours() - 2)
    const result = formatRelativeDate(date)
    expect(result).toContain('ago')
  })

  it('should return invalid date for invalid input', () => {
    const result = formatRelativeDate('not-a-date')
    expect(result).toBe('Invalid date')
  })

  it('should handle future dates', () => {
    const date = new Date()
    date.setDate(date.getDate() + 1)
    const result = formatRelativeDate(date.toISOString())
    expect(result).toContain('in')
  })
})

describe('getSeverityColor', () => {
  it('should return critical color classes', () => {
    const result = getSeverityColor('Critical')
    expect(result).toContain('red')
  })

  it('should return high color classes', () => {
    const result = getSeverityColor('High')
    expect(result).toContain('orange')
  })

  it('should return medium color classes', () => {
    const result = getSeverityColor('Medium')
    expect(result).toContain('yellow')
  })

  it('should return low color classes', () => {
    const result = getSeverityColor('Low')
    expect(result).toContain('blue')
  })

  it('should return info color classes', () => {
    const result = getSeverityColor('Info')
    expect(result).toContain('gray')
  })

  it('should handle lowercase input', () => {
    const result = getSeverityColor('critical')
    expect(result).toContain('red')
  })

  it('should handle mixed case input', () => {
    const result = getSeverityColor('CrItIcAl')
    expect(result).toContain('red')
  })

  it('should return info color for unknown severity', () => {
    const result = getSeverityColor('unknown')
    expect(result).toContain('gray')
  })
})

describe('getSeverityTextColor', () => {
  it('should return critical text color', () => {
    const result = getSeverityTextColor('Critical')
    expect(result).toContain('text-red')
  })

  it('should return high text color', () => {
    const result = getSeverityTextColor('High')
    expect(result).toContain('text-orange')
  })

  it('should return medium text color', () => {
    const result = getSeverityTextColor('Medium')
    expect(result).toContain('text-yellow')
  })

  it('should return low text color', () => {
    const result = getSeverityTextColor('Low')
    expect(result).toContain('text-blue')
  })

  it('should return info text color for unknown', () => {
    const result = getSeverityTextColor('Unknown')
    expect(result).toContain('text-gray')
  })
})

describe('getStatusColor', () => {
  it('should return completed color classes', () => {
    const result = getStatusColor('completed')
    expect(result).toContain('green')
  })

  it('should return running color classes', () => {
    const result = getStatusColor('running')
    expect(result).toContain('blue')
  })

  it('should return pending color classes', () => {
    const result = getStatusColor('pending')
    expect(result).toContain('yellow')
  })

  it('should return failed color classes', () => {
    const result = getStatusColor('failed')
    expect(result).toContain('red')
  })

  it('should return cancelled color classes', () => {
    const result = getStatusColor('cancelled')
    expect(result).toContain('gray')
  })

  it('should handle uppercase input', () => {
    const result = getStatusColor('COMPLETED')
    expect(result).toContain('green')
  })

  it('should return pending color for unknown status', () => {
    const result = getStatusColor('unknown')
    expect(result).toContain('yellow')
  })
})

describe('truncate', () => {
  it('should truncate long strings', () => {
    const result = truncate('This is a long string that needs truncation', 20)
    expect(result.length).toBe(23) // 20 + 3 for '...'
    expect(result.endsWith('...')).toBe(true)
  })

  it('should not truncate short strings', () => {
    const result = truncate('Short string', 20)
    expect(result).toBe('Short string')
  })

  it('should handle exact length strings', () => {
    const result = truncate('Exactly twenty chars', 20)
    expect(result).toBe('Exactly twenty chars')
  })

  it('should handle empty string', () => {
    const result = truncate('', 10)
    expect(result).toBe('')
  })

  it('should handle length of 0', () => {
    const result = truncate('Any string', 0)
    expect(result).toBe('...')
  })

  it('should handle single character', () => {
    const result = truncate('A', 5)
    expect(result).toBe('A')
  })
})