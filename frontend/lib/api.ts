/**
 * VulnScope - API Service
 * Centralized API client for all backend communications
 */

import axios, { AxiosInstance, AxiosError } from 'axios'

// Types
export interface Target {
  id: string
  name: string
  url: string
  description?: string
  tags?: string[]
  auth_type?: string
  created_at: string
  updated_at?: string
}

export interface TargetCreate {
  name: string
  url: string
  description?: string
  tags?: string[]
  auth_type?: string
  auth_config?: Record<string, unknown>
}

export interface Scan {
  id: string
  target_id: string
  name: string
  description?: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
  scan_type?: string
  progress?: number
  endpoints_discovered?: number
  findings_count?: number
  created_at: string
  started_at?: string
  completed_at?: string
  target?: Target
}

export interface ScanCreate {
  target_id: string
  name: string
  description?: string
  scan_type?: string
  enable_crawler?: boolean
  enable_openapi_import?: boolean
  enable_graphql_import?: boolean
  enable_dast?: boolean
  enable_fuzzer?: boolean
}

export interface Finding {
  id: string
  scan_id: string
  target_id: string
  title: string
  description?: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  vuln_type: string
  url?: string
  method?: string
  parameter?: string
  payload?: string
  evidence?: string
  status: 'Open' | 'In Progress' | 'Resolved' | 'False Positive'
  cvss_score?: number
  cwe_id?: string
  owasp_category?: string
  created_at: string
  target?: Target
}

export interface FindingListResponse {
  total: number
  findings: Finding[]
}

export interface Report {
  id: string
  scan_id: string
  name: string
  format: 'json' | 'html' | 'csv' | 'sarif' | 'pdf'
  size?: string
  created_at: string
  download_url?: string
}

export interface ReportCreate {
  scan_id: string
  name: string
  format: string
  include_evidence?: boolean
}

export interface ComplianceStandard {
  name: string
  score: number
  status: 'pass' | 'warning' | 'fail'
  requirements_met: number
  requirements_total: number
}

export interface ComplianceCategory {
  name: string
  score: number
}

export interface ComplianceResponse {
  standard: string
  compliant: boolean
  score: number
  violations: Array<{
    requirement: string
    status: string
    details?: string
  }>
}

export interface DashboardStats {
  total_scans: number
  active_scans: number
  total_findings: number
  critical_findings: number
  high_findings: number
  medium_findings: number
  low_findings: number
  scans_change: number
  critical_change: number
  high_change: number
}

export interface DashboardTrend {
  period: string
  count: number
}

export interface Settings {
  api_url: string
  max_concurrent: number
  timeout: number
  rate_limit: number
  email_notifications: boolean
  slack_integration: boolean
  default_theme: 'light' | 'dark'
  auto_refresh: boolean
}

// API Client
class APIClient {
  private client: AxiosInstance
  private baseURL: string

  constructor() {
    // Always use relative '/api' to go through Next.js API routes
    // This ensures proper proxying to the backend and avoids CORS issues
    // The Next.js API routes will forward requests to the actual backend
    this.baseURL = '/api'
    
    this.client = axios.create({
      baseURL: this.baseURL,
      timeout: 30000,
      headers: {
        'Content-Type': 'application/json',
      },
    })

    // Request interceptor
    this.client.interceptors.request.use(
      (config) => {
        // Add auth token if available
        if (typeof window !== 'undefined') {
          const token = localStorage.getItem('auth_token')
          if (token) {
            config.headers.Authorization = `Bearer ${token}`
          }
        }
        return config
      },
      (error) => Promise.reject(error)
    )

    // Response interceptor
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response?.status === 401) {
          // Handle unauthorized
          if (typeof window !== 'undefined') {
            localStorage.removeItem('auth_token')
            window.location.href = '/login'
          }
        }
        return Promise.reject(error)
      }
    )
  }

  // Targets
  async getTargets(): Promise<Target[]> {
    const response = await this.client.get('/targets')
    return response.data
  }

  async getTarget(id: string): Promise<Target> {
    const response = await this.client.get(`/targets/${id}`)
    return response.data
  }

  async createTarget(data: TargetCreate): Promise<Target> {
    const response = await this.client.post('/targets', data)
    return response.data
  }

  async updateTarget(id: string, data: Partial<TargetCreate>): Promise<Target> {
    const response = await this.client.put(`/targets/${id}`, data)
    return response.data
  }

  async deleteTarget(id: string): Promise<void> {
    await this.client.delete(`/targets/${id}`)
  }

  // Scans
  async getScans(params?: { target_id?: string; status?: string }): Promise<Scan[]> {
    const response = await this.client.get('/scans', { params })
    return response.data
  }

  async getScan(id: string): Promise<Scan> {
    const response = await this.client.get(`/scans/${id}`)
    return response.data
  }

  async createScan(data: ScanCreate): Promise<Scan> {
    const response = await this.client.post('/scans', data)
    return response.data
  }

  async getScanStatus(id: string): Promise<Scan> {
    const response = await this.client.get(`/scans/${id}/status`)
    return response.data
  }

  async cancelScan(id: string): Promise<void> {
    await this.client.post(`/scans/${id}/cancel`)
  }

  // Findings
  async getFindings(params?: {
    scan_id?: string
    target_id?: string
    severity?: string
    vuln_type?: string
    status?: string
    skip?: number
    limit?: number
  }): Promise<FindingListResponse> {
    const response = await this.client.get('/findings', { params })
    return response.data
  }

  async getFinding(id: string): Promise<Finding> {
    const response = await this.client.get(`/findings/${id}`)
    return response.data
  }

  async updateFinding(id: string, data: { status?: string; false_positive?: boolean }): Promise<Finding> {
    const response = await this.client.patch(`/findings/${id}`, data)
    return response.data
  }

  async verifyFinding(id: string, verified: boolean): Promise<Finding> {
    const response = await this.client.post(`/findings/${id}/verify`, { verified })
    return response.data
  }

  // Reports
  async getReports(): Promise<Report[]> {
    const response = await this.client.get('/reports')
    return response.data
  }

  async generateReport(data: ReportCreate): Promise<Report> {
    const response = await this.client.post('/reports/generate', data)
    return response.data
  }

  async downloadReport(id: string): Promise<Blob> {
    const response = await this.client.get(`/reports/${id}/download`, {
      responseType: 'blob'
    })
    return response.data
  }

  // Compliance
  async getComplianceStandards(): Promise<ComplianceStandard[]> {
    const response = await this.client.get('/compliance/standards')
    return response.data.standards
  }

  async checkCompliance(standard: string): Promise<ComplianceResponse> {
    const response = await this.client.post('/compliance/check', { standard })
    return response.data
  }

  // Dashboard
  async getDashboardStats(): Promise<DashboardStats> {
    const response = await this.client.get('/dashboard/stats')
    return response.data
  }

  async getDashboardTrends(): Promise<DashboardTrend[]> {
    const response = await this.client.get('/dashboard/trends')
    return response.data
  }

  // Settings
  async getSettings(): Promise<Settings> {
    const response = await this.client.get('/settings')
    return response.data
  }

  async updateSettings(data: Partial<Settings>): Promise<Settings> {
    const response = await this.client.put('/settings', data)
    return response.data
  }
}

// Export singleton instance
export const api = new APIClient()
export default api