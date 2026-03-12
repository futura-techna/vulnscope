/**
 * VulnScope - API Client Tests
 */

import axios from 'axios'

// Mock axios
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

jest.mock('axios', () => ({
  create: jest.fn(() => mockAxiosInstance),
}))

// Mock localStorage
const localStorageMock = {
  getItem: jest.fn(),
  setItem: jest.fn(),
  removeItem: jest.fn(),
  clear: jest.fn(),
}
Object.defineProperty(window, 'localStorage', { value: localStorageMock })

// Import after mocking
let api: any

describe('APIClient', () => {
  beforeAll(() => {
    // Reimport the api after mocks are set up
    jest.resetModules()
    api = require('./api').api
  })

  beforeEach(() => {
    jest.clearAllMocks()
  })

  describe('Targets', () => {
    it('should fetch targets', async () => {
      const mockTargets = [{ id: '1', name: 'Target 1' }]
      mockAxiosInstance.get.mockResolvedValue({ data: mockTargets })
      
      const result = await api.getTargets()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/targets')
      expect(result).toEqual(mockTargets)
    })

    it('should get a single target', async () => {
      const mockTarget = { id: '1', name: 'Target 1' }
      mockAxiosInstance.get.mockResolvedValue({ data: mockTarget })
      
      const result = await api.getTarget('1')
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/targets/1')
      expect(result).toEqual(mockTarget)
    })

    it('should create a target', async () => {
      const newTarget = { name: 'New Target', url: 'https://example.com' }
      const createdTarget = { id: '1', ...newTarget }
      mockAxiosInstance.post.mockResolvedValue({ data: createdTarget })
      
      const result = await api.createTarget(newTarget)
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/targets', newTarget)
      expect(result).toEqual(createdTarget)
    })

    it('should update a target', async () => {
      const updatedTarget = { id: '1', name: 'Updated Target' }
      mockAxiosInstance.put.mockResolvedValue({ data: updatedTarget })
      
      const result = await api.updateTarget('1', { name: 'Updated Target' })
      
      expect(mockAxiosInstance.put).toHaveBeenCalledWith('/targets/1', { name: 'Updated Target' })
    })

    it('should delete a target', async () => {
      mockAxiosInstance.delete.mockResolvedValue({ data: {} })
      
      await api.deleteTarget('target-1')
      
      expect(mockAxiosInstance.delete).toHaveBeenCalledWith('/targets/target-1')
    })
  })

  describe('Scans', () => {
    it('should fetch scans', async () => {
      const mockScans = [{ id: '1', name: 'Scan 1', status: 'completed' }]
      mockAxiosInstance.get.mockResolvedValue({ data: mockScans })
      
      const result = await api.getScans()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/scans', { params: undefined })
      expect(result).toEqual(mockScans)
    })

    it('should fetch scans with filters', async () => {
      const mockScans = [{ id: '1', target_id: 'target-1' }]
      mockAxiosInstance.get.mockResolvedValue({ data: mockScans })
      
      const result = await api.getScans({ target_id: 'target-1' })
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/scans', { params: { target_id: 'target-1' } })
    })

    it('should get a single scan', async () => {
      const mockScan = { id: '1', name: 'Scan 1' }
      mockAxiosInstance.get.mockResolvedValue({ data: mockScan })
      
      const result = await api.getScan('1')
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/scans/1')
    })

    it('should create a scan', async () => {
      const newScan = { target_id: 'target-1', name: 'Test Scan' }
      const createdScan = { id: '1', ...newScan, status: 'pending' }
      mockAxiosInstance.post.mockResolvedValue({ data: createdScan })
      
      const result = await api.createScan(newScan)
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/scans', newScan)
    })

    it('should get scan status', async () => {
      const mockStatus = { id: '1', status: 'running', progress: 50 }
      mockAxiosInstance.get.mockResolvedValue({ data: mockStatus })
      
      const result = await api.getScanStatus('1')
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/scans/1/status')
    })

    it('should cancel a scan', async () => {
      mockAxiosInstance.post.mockResolvedValue({ data: {} })
      
      await api.cancelScan('scan-1')
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/scans/scan-1/cancel')
    })
  })

  describe('Findings', () => {
    it('should fetch findings', async () => {
      const mockResponse = { total: 2, findings: [{ id: '1' }, { id: '2' }] }
      mockAxiosInstance.get.mockResolvedValue({ data: mockResponse })
      
      const result = await api.getFindings()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/findings', { params: undefined })
      expect(result).toEqual(mockResponse)
    })

    it('should fetch findings with filters', async () => {
      const mockResponse = { total: 1, findings: [{ id: '1', severity: 'Critical' }] }
      mockAxiosInstance.get.mockResolvedValue({ data: mockResponse })
      
      const result = await api.getFindings({ severity: 'Critical' })
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/findings', { params: { severity: 'Critical' } })
    })

    it('should get a single finding', async () => {
      const mockFinding = { id: '1', title: 'XSS', severity: 'High' }
      mockAxiosInstance.get.mockResolvedValue({ data: mockFinding })
      
      const result = await api.getFinding('1')
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/findings/1')
    })

    it('should update a finding', async () => {
      const updatedFinding = { id: '1', status: 'Resolved' }
      mockAxiosInstance.patch.mockResolvedValue({ data: updatedFinding })
      
      const result = await api.updateFinding('1', { status: 'Resolved' })
      
      expect(mockAxiosInstance.patch).toHaveBeenCalledWith('/findings/1', { status: 'Resolved' })
    })

    it('should verify a finding', async () => {
      const mockFinding = { id: '1', verified: true }
      mockAxiosInstance.post.mockResolvedValue({ data: mockFinding })
      
      const result = await api.verifyFinding('1', true)
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/findings/1/verify', { verified: true })
    })
  })

  describe('Reports', () => {
    it('should fetch reports', async () => {
      const mockReports = [{ id: '1', name: 'Report 1' }]
      mockAxiosInstance.get.mockResolvedValue({ data: mockReports })
      
      const result = await api.getReports()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/reports')
    })

    it('should generate a report', async () => {
      const newReport = { scan_id: 'scan-1', name: 'Report', format: 'pdf' }
      const createdReport = { id: '1', ...newReport }
      mockAxiosInstance.post.mockResolvedValue({ data: createdReport })
      
      const result = await api.generateReport(newReport)
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/reports/generate', newReport)
    })
  })

  describe('Compliance', () => {
    it('should fetch compliance standards', async () => {
      const mockStandards = [{ name: 'OWASP', score: 85 }]
      mockAxiosInstance.get.mockResolvedValue({ data: { standards: mockStandards } })
      
      const result = await api.getComplianceStandards()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/compliance/standards')
      expect(result).toEqual(mockStandards)
    })

    it('should check compliance', async () => {
      const mockResponse = { standard: 'OWASP', compliant: true, score: 95 }
      mockAxiosInstance.post.mockResolvedValue({ data: mockResponse })
      
      const result = await api.checkCompliance('OWASP')
      
      expect(mockAxiosInstance.post).toHaveBeenCalledWith('/compliance/check', { standard: 'OWASP' })
    })
  })

  describe('Dashboard', () => {
    it('should fetch dashboard stats', async () => {
      const mockStats = { total_scans: 10, total_findings: 25 }
      mockAxiosInstance.get.mockResolvedValue({ data: mockStats })
      
      const result = await api.getDashboardStats()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/dashboard/stats')
    })

    it('should fetch dashboard trends', async () => {
      const mockTrends = [{ period: '2024-01', count: 5 }]
      mockAxiosInstance.get.mockResolvedValue({ data: mockTrends })
      
      const result = await api.getDashboardTrends()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/dashboard/trends')
    })
  })

  describe('Settings', () => {
    it('should fetch settings', async () => {
      const mockSettings = { max_concurrent: 10, timeout: 30 }
      mockAxiosInstance.get.mockResolvedValue({ data: mockSettings })
      
      const result = await api.getSettings()
      
      expect(mockAxiosInstance.get).toHaveBeenCalledWith('/settings')
    })

    it('should update settings', async () => {
      const updatedSettings = { max_concurrent: 20 }
      mockAxiosInstance.put.mockResolvedValue({ data: updatedSettings })
      
      const result = await api.updateSettings(updatedSettings)
      
      expect(mockAxiosInstance.put).toHaveBeenCalledWith('/settings', updatedSettings)
    })
  })
})