// VulnScope - useApi Hooks Tests
// Tests for React Query hooks

import { renderHook, waitFor, act } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import React from 'react'
import {
  useTargets,
  useTarget,
  useCreateTarget,
  useUpdateTarget,
  useDeleteTarget,
  useScans,
  useScan,
  useCreateScan,
  useCancelScan,
  useFindings,
  useFinding,
  useUpdateFinding,
  useVerifyFinding,
  useReports,
  useGenerateReport,
  useCompliance,
  useComplianceCategories,
  useDashboardStats,
  useSettings,
  useUpdateSettings,
} from './useApi'

// Mock the api module
jest.mock('../api', () => ({
  __esModule: true,
  default: {
    getTargets: jest.fn(),
    getTarget: jest.fn(),
    createTarget: jest.fn(),
    updateTarget: jest.fn(),
    deleteTarget: jest.fn(),
    getScans: jest.fn(),
    getScan: jest.fn(),
    createScan: jest.fn(),
    cancelScan: jest.fn(),
    getFindings: jest.fn(),
    getFinding: jest.fn(),
    updateFinding: jest.fn(),
    verifyFinding: jest.fn(),
    getReports: jest.fn(),
    generateReport: jest.fn(),
    checkCompliance: jest.fn(),
    getSettings: jest.fn(),
    updateSettings: jest.fn(),
    client: {
      get: jest.fn(),
      post: jest.fn(),
    },
  },
}))

const mockApi = require('../api').default

// Create wrapper with QueryClient
const createWrapper = () => {
  const queryClient = new QueryClient({
    defaultOptions: {
      queries: {
        retry: false,
      },
    },
  })
  
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  )
}

describe('useTargets', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches targets successfully', async () => {
    const mockTargets = [
      { id: '1', name: 'Target 1', url: 'http://example.com' },
      { id: '2', name: 'Target 2', url: 'http://example2.com' },
    ]
    mockApi.getTargets.mockResolvedValue(mockTargets)

    const { result } = renderHook(() => useTargets(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockTargets)
    expect(mockApi.getTargets).toHaveBeenCalledTimes(1)
  })

  it('handles error when fetching targets', async () => {
    mockApi.getTargets.mockRejectedValue(new Error('Network error'))

    const { result } = renderHook(() => useTargets(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isError).toBe(true)
    })

    expect(result.current.error).toBeDefined()
  })
})

describe('useTarget', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches a single target by id', async () => {
    const mockTarget = { id: '1', name: 'Target 1', url: 'http://example.com' }
    mockApi.getTarget.mockResolvedValue(mockTarget)

    const { result } = renderHook(() => useTarget('1'), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockTarget)
    expect(mockApi.getTarget).toHaveBeenCalledWith('1')
  })

  it('does not fetch when id is empty', () => {
    const { result } = renderHook(() => useTarget(''), { wrapper: createWrapper() })

    expect(result.current.isFetching).toBe(false)
    expect(mockApi.getTarget).not.toHaveBeenCalled()
  })
})

describe('useCreateTarget', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('creates a target successfully', async () => {
    const newTarget = { name: 'New Target', url: 'http://new.example.com' }
    const createdTarget = { id: '3', ...newTarget }
    mockApi.createTarget.mockResolvedValue(createdTarget)

    const { result } = renderHook(() => useCreateTarget(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate(newTarget)
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.createTarget).toHaveBeenCalledWith(newTarget)
  })
})

describe('useUpdateTarget', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('updates a target successfully', async () => {
    const updatedTarget = { id: '1', name: 'Updated Target', url: 'http://updated.example.com' }
    mockApi.updateTarget.mockResolvedValue(updatedTarget)

    const { result } = renderHook(() => useUpdateTarget(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate({ id: '1', data: { name: 'Updated Target' } })
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.updateTarget).toHaveBeenCalledWith('1', { name: 'Updated Target' })
  })
})

describe('useDeleteTarget', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('deletes a target successfully', async () => {
    mockApi.deleteTarget.mockResolvedValue({ success: true })

    const { result } = renderHook(() => useDeleteTarget(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate('1')
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.deleteTarget).toHaveBeenCalledWith('1')
  })
})

describe('useScans', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches scans successfully', async () => {
    const mockScans = [
      { id: '1', name: 'Scan 1', status: 'completed' },
      { id: '2', name: 'Scan 2', status: 'running' },
    ]
    mockApi.getScans.mockResolvedValue(mockScans)

    const { result } = renderHook(() => useScans(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockScans)
  })

  it('fetches scans with params', async () => {
    const mockScans = [{ id: '1', name: 'Scan 1', status: 'completed' }]
    mockApi.getScans.mockResolvedValue(mockScans)

    const { result } = renderHook(() => useScans({ target_id: 'target-1', status: 'completed' }), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.getScans).toHaveBeenCalledWith({ target_id: 'target-1', status: 'completed' })
  })
})

describe('useScan', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches a single scan by id', async () => {
    const mockScan = { id: '1', name: 'Scan 1', status: 'completed', progress: 100 }
    mockApi.getScan.mockResolvedValue(mockScan)

    const { result } = renderHook(() => useScan('1'), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockScan)
  })
})

describe('useCreateScan', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('creates a scan successfully', async () => {
    const newScan = { target_id: '1', name: 'New Scan' }
    const createdScan = { id: '1', ...newScan, status: 'pending' }
    mockApi.createScan.mockResolvedValue(createdScan)

    const { result } = renderHook(() => useCreateScan(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate(newScan)
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.createScan).toHaveBeenCalledWith(newScan)
  })
})

describe('useCancelScan', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('cancels a scan successfully', async () => {
    mockApi.cancelScan.mockResolvedValue({ status: 'cancelled' })

    const { result } = renderHook(() => useCancelScan(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate('1')
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.cancelScan).toHaveBeenCalledWith('1')
  })
})

describe('useFindings', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches findings successfully', async () => {
    const mockFindings = {
      findings: [
        { id: '1', title: 'XSS', severity: 'High' },
        { id: '2', title: 'SQLi', severity: 'Critical' },
      ],
      total: 2,
    }
    mockApi.getFindings.mockResolvedValue(mockFindings)

    const { result } = renderHook(() => useFindings(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockFindings)
  })

  it('fetches findings with filters', async () => {
    const mockFindings = {
      findings: [{ id: '1', title: 'SQLi', severity: 'Critical' }],
      total: 1,
    }
    mockApi.getFindings.mockResolvedValue(mockFindings)

    const { result } = renderHook(() => useFindings({ severity: 'Critical' }), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.getFindings).toHaveBeenCalledWith({ severity: 'Critical' })
  })
})

describe('useFinding', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches a single finding by id', async () => {
    const mockFinding = { id: '1', title: 'XSS', severity: 'High' }
    mockApi.getFinding.mockResolvedValue(mockFinding)

    const { result } = renderHook(() => useFinding('1'), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockFinding)
  })
})

describe('useUpdateFinding', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('updates a finding successfully', async () => {
    mockApi.updateFinding.mockResolvedValue({ success: true })

    const { result } = renderHook(() => useUpdateFinding(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate({ id: '1', data: { status: 'confirmed' } })
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.updateFinding).toHaveBeenCalledWith('1', { status: 'confirmed' })
  })
})

describe('useVerifyFinding', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('verifies a finding successfully', async () => {
    mockApi.verifyFinding.mockResolvedValue({ verified: true })

    const { result } = renderHook(() => useVerifyFinding(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate({ id: '1', verified: true })
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.verifyFinding).toHaveBeenCalledWith('1', true)
  })
})

describe('useReports', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches reports successfully', async () => {
    const mockReports = [
      { id: '1', name: 'Report 1', format: 'json' },
      { id: '2', name: 'Report 2', format: 'html' },
    ]
    mockApi.getReports.mockResolvedValue(mockReports)

    const { result } = renderHook(() => useReports(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockReports)
  })
})

describe('useGenerateReport', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('generates a report successfully', async () => {
    const mockReport = { id: '1', scan_id: 'scan-1', format: 'json' }
    mockApi.generateReport.mockResolvedValue(mockReport)

    const { result } = renderHook(() => useGenerateReport(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate({ scan_id: 'scan-1', format: 'json' })
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.generateReport).toHaveBeenCalledWith({ scan_id: 'scan-1', format: 'json' })
  })
})

describe('useCompliance', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches compliance standards successfully', async () => {
    mockApi.client.get.mockResolvedValue({
      data: {
        standards: [
          { name: 'PCI-DSS', score: 95 },
          { name: 'NIS2', score: 90 },
        ],
      },
    })

    const { result } = renderHook(() => useCompliance(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toBeDefined()
  })

  it('returns default data on error', async () => {
    mockApi.client.get.mockRejectedValue(new Error('Network error'))

    const { result } = renderHook(() => useCompliance(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    // Should return default data
    expect(result.current.data).toBeDefined()
    expect(result.current.data.length).toBeGreaterThan(0)
  })
})

describe('useComplianceCategories', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches compliance categories successfully', async () => {
    mockApi.client.get.mockResolvedValue({
      data: {
        categories: [
          { name: 'Access Control', score: 95 },
          { name: 'Encryption', score: 98 },
        ],
      },
    })

    const { result } = renderHook(() => useComplianceCategories(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toBeDefined()
  })
})

describe('useDashboardStats', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('calculates dashboard stats from multiple endpoints', async () => {
    mockApi.getTargets.mockResolvedValue([
      { id: '1', name: 'Target 1' },
      { id: '2', name: 'Target 2' },
    ])
    mockApi.getScans.mockResolvedValue([
      { id: '1', status: 'completed' },
      { id: '2', status: 'running' },
    ])
    mockApi.getFindings.mockResolvedValue({
      findings: [
        { severity: 'Critical' },
        { severity: 'High' },
        { severity: 'Medium' },
        { severity: 'Low' },
      ],
      total: 4,
    })

    const { result } = renderHook(() => useDashboardStats(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data.total_targets).toBe(2)
    expect(result.current.data.total_scans).toBe(2)
    expect(result.current.data.active_scans).toBe(1)
    expect(result.current.data.total_findings).toBe(4)
  })
})

describe('useSettings', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('fetches settings successfully', async () => {
    const mockSettings = { app_name: 'VulnScope', version: '1.0' }
    mockApi.getSettings.mockResolvedValue(mockSettings)

    const { result } = renderHook(() => useSettings(), { wrapper: createWrapper() })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(result.current.data).toEqual(mockSettings)
  })
})

describe('useUpdateSettings', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('updates settings successfully', async () => {
    mockApi.updateSettings.mockResolvedValue({ success: true })

    const { result } = renderHook(() => useUpdateSettings(), { wrapper: createWrapper() })

    await act(async () => {
      result.current.mutate({ app_name: 'New Name' })
    })

    await waitFor(() => {
      expect(result.current.isSuccess).toBe(true)
    })

    expect(mockApi.updateSettings).toHaveBeenCalledWith({ app_name: 'New Name' })
  })
})