/**
 * VulnScope - API Client Tests
 */

import api, { APIClient } from './api'

// Mock axios
jest.mock('axios', () => {
  const mockAxiosInstance = {
    get: jest.fn(),
    post: jest.fn(),
    put: jest.fn(),
    patch: jest.fn(),
    delete: jest.fn(),
    interceptors: {
      request: { use: jest.fn() },
      response: { use: jest.fn() }
    }
  }
  return {
    create: jest.fn(() => mockAxiosInstance),
    default: mockAxiosInstance
  }
})

describe('APIClient', () => {
  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Targets', () => {
    it('should fetch targets', async () => {
      const mockTargets = [{ id: '1', name: 'Target 1' }]
      api.client.get = jest.fn().mockResolvedValue({ data: mockTargets })
      
      const result = await api.getTargets()
      
      expect(api.client.get).toHaveBeenCalledWith('/targets')
      expect(result).toEqual(mockTargets)
    })

    it('should create a target', async () => {
      const newTarget = { name: 'New Target', url: 'https://example.com' }
      const createdTarget = { id: '1', ...newTarget }
      api.client.post = jest.fn().mockResolvedValue({ data: createdTarget })
      
      const result = await api.createTarget(newTarget)
      
      expect(api.client.post).toHaveBeenCalledWith('/targets', newTarget)
      expect(result).toEqual(createdTarget)
    })

    it('should delete a target', async () => {
      api.client.delete = jest.fn().mockResolvedValue({ data: {} })
      
      await api.deleteTarget('target-1')
      
      expect(api.client.delete).toHaveBeenCalledWith('/targets/target-1')
    })
  })

  describe('Scans', () => {
    it('should fetch scans', async () => {
      const mockScans = [{ id: '1', name: 'Scan 1', status: 'completed' }]
      api.client.get = jest.fn().mockResolvedValue({ data: mockScans })
      
      const result = await api.getScans()
      
      expect(api.client.get).toHaveBeenCalledWith('/scans', { params: undefined })
      expect(result).toEqual(mockScans)
    })

    it('should fetch scans with filters', async () => {
      const mockScans = [{ id: '1', target_id: 'target-1' }]
      api.client.get = jest.fn().mockResolvedValue({ data: mockScans })
      
      const result = await api.getScans({ target_id: 'target-1' })
      
      expect(api.client.get).toHaveBeenCalledWith('/scans', { params: { target_id: 'target-1' } })
    })

    it('should create a scan', async () => {
      const newScan = { target_id: 'target-1', name: 'Test Scan' }
      const createdScan = { id: '1', ...newScan, status: 'pending' }
      api.client.post = jest.fn().mockResolvedValue({ data: createdScan })
      
      const result = await api.createScan(newScan)
      
      expect(api.client.post).toHaveBeenCalledWith('/scans', newScan)
    })

    it('should cancel a scan', async () => {
      api.client.post = jest.fn().mockResolvedValue({ data: {} })
      
      await api.cancelScan('scan-1')
      
      expect(api.client.post).toHaveBeenCalledWith('/scans/scan-1/cancel')
    })
  })

  describe('Findings', () => {
    it('should fetch findings', async () => {
      const mockResponse = { total: 2, findings: [{ id: '1' }, { id: '2' }] }
      api.client.get = jest.fn().mockResolvedValue({ data: mockResponse })
      
      const result = await api.getFindings()
      
      expect(api.client.get).toHaveBeenCalledWith('/findings', { params: undefined })
      expect(result).toEqual(mockResponse)
    })

    it('should fetch findings with filters', async () => {
      const mockResponse = { total: 1, findings: [{ id: '1', severity: 'Critical' }] }
      api.client.get = jest.fn().mockResolvedValue({ data: mockResponse })
      
      const result = await api.getFindings({ severity: 'Critical' })
      
      expect(api.client.get).toHaveBeenCalledWith('/findings', { params: { severity: 'Critical' } })
    })

    it('should update a finding', async () => {
      const updatedFinding = { id: '1', status: 'Resolved' }
      api.client.patch = jest.fn().mockResolvedValue({ data: updatedFinding })
      
      const result = await api.updateFinding('1', { status: 'Resolved' })
      
      expect(api.client.patch).toHaveBeenCalledWith('/findings/1', { status: 'Resolved' })
    })
  })

  describe('Reports', () => {
    it('should generate a report', async () => {
      const newReport = { scan_id: 'scan-1', name: 'Report', format: 'pdf' }
      const createdReport = { id: '1', ...newReport }
      api.client.post = jest.fn().mockResolvedValue({ data: createdReport })
      
      const result = await api.generateReport(newReport)
      
      expect(api.client.post).toHaveBeenCalledWith('/reports/generate', newReport)
    })
  })

  describe('Dashboard', () => {
    it('should fetch dashboard stats', async () => {
      const mockStats = { total_scans: 10, total_findings: 25 }
      api.client.get = jest.fn().mockResolvedValue({ data: mockStats })
      
      const result = await api.getDashboardStats()
      
      expect(api.client.get).toHaveBeenCalledWith('/dashboard/stats')
    })
  })

  describe('Settings', () => {
    it('should fetch settings', async () => {
      const mockSettings = { max_concurrent: 10, timeout: 30 }
      api.client.get = jest.fn().mockResolvedValue({ data: mockSettings })
      
      const result = await api.getSettings()
      
      expect(api.client.get).toHaveBeenCalledWith('/settings')
    })

    it('should update settings', async () => {
      const updatedSettings = { max_concurrent: 20 }
      api.client.put = jest.fn().mockResolvedValue({ data: updatedSettings })
      
      const result = await api.updateSettings(updatedSettings)
      
      expect(api.client.put).toHaveBeenCalledWith('/settings', updatedSettings)
    })
  })
})