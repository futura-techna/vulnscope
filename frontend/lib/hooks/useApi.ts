/**
 * VulnScope - React Query Hooks
 * Custom hooks for data fetching and mutations
 */

'use client'

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api, { 
  Target, TargetCreate, 
  Scan, ScanCreate,
  Finding, FindingListResponse,
  Report, ReportCreate,
  ComplianceStandard, ComplianceResponse,
  DashboardStats, DashboardTrend,
  Settings
} from '../api'

// Query Keys
export const queryKeys = {
  targets: ['targets'] as const,
  target: (id: string) => ['targets', id] as const,
  scans: ['scans'] as const,
  scansByTarget: (targetId: string) => ['scans', targetId] as const,
  scan: (id: string) => ['scans', id] as const,
  findings: ['findings'] as const,
  finding: (id: string) => ['findings', id] as const,
  reports: ['reports'] as const,
  compliance: ['compliance'] as const,
  complianceStandard: (standard: string) => ['compliance', standard] as const,
  dashboard: ['dashboard'] as const,
  settings: ['settings'] as const,
}

// ============ Targets Hooks ============

export function useTargets() {
  return useQuery({
    queryKey: queryKeys.targets,
    queryFn: () => api.getTargets(),
    staleTime: 30000, // 30 seconds
  })
}

export function useTarget(id: string) {
  return useQuery({
    queryKey: queryKeys.target(id),
    queryFn: () => api.getTarget(id),
    enabled: !!id,
  })
}

export function useCreateTarget() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: TargetCreate) => api.createTarget(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets })
    },
  })
}

export function useUpdateTarget() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<TargetCreate> }) => 
      api.updateTarget(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets })
      queryClient.invalidateQueries({ queryKey: queryKeys.target(variables.id) })
    },
  })
}

export function useDeleteTarget() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (id: string) => api.deleteTarget(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.targets })
    },
  })
}

// ============ Scans Hooks ============

export function useScans(params?: { target_id?: string; status?: string }) {
  return useQuery({
    queryKey: [...queryKeys.scans, params],
    queryFn: () => api.getScans(params),
    staleTime: 10000, // 10 seconds - more frequent updates for scans
    refetchInterval: 5000, // Auto-refetch every 5 seconds for active scans
  })
}

export function useScan(id: string) {
  return useQuery({
    queryKey: queryKeys.scan(id),
    queryFn: () => api.getScan(id),
    enabled: !!id,
    refetchInterval: (query) => {
      // Refetch more frequently for running scans
      const data = query.state.data as Scan | undefined
      if (data?.status === 'running' || data?.status === 'pending') {
        return 3000
      }
      return false
    },
  })
}

export function useCreateScan() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: ScanCreate) => api.createScan(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scans })
    },
  })
}

export function useCancelScan() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (id: string) => api.cancelScan(id),
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.scan(id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.scans })
    },
  })
}

// ============ Findings Hooks ============

export function useFindings(params?: {
  scan_id?: string
  target_id?: string
  severity?: string
  vuln_type?: string
  status?: string
  skip?: number
  limit?: number
}) {
  return useQuery({
    queryKey: [...queryKeys.findings, params],
    queryFn: () => api.getFindings(params),
    staleTime: 30000,
  })
}

export function useFinding(id: string) {
  return useQuery({
    queryKey: queryKeys.finding(id),
    queryFn: () => api.getFinding(id),
    enabled: !!id,
  })
}

export function useUpdateFinding() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: { status?: string; false_positive?: boolean } }) =>
      api.updateFinding(id, data),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.findings })
      queryClient.invalidateQueries({ queryKey: queryKeys.finding(variables.id) })
    },
  })
}

export function useVerifyFinding() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: ({ id, verified }: { id: string; verified: boolean }) =>
      api.verifyFinding(id, verified),
    onSuccess: (_, variables) => {
      queryClient.invalidateQueries({ queryKey: queryKeys.finding(variables.id) })
      queryClient.invalidateQueries({ queryKey: queryKeys.findings })
    },
  })
}

// ============ Reports Hooks ============

export function useReports() {
  return useQuery({
    queryKey: queryKeys.reports,
    queryFn: () => api.getReports(),
    staleTime: 60000, // 1 minute
  })
}

export function useGenerateReport() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: ReportCreate) => api.generateReport(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.reports })
    },
  })
}

// ============ Compliance Hooks ============

export function useCompliance() {
  return useQuery({
    queryKey: queryKeys.compliance,
    queryFn: async () => {
      const standards = await api.getComplianceStandards()
      return standards
    },
    staleTime: 300000, // 5 minutes
  })
}

export function useComplianceCheck(standard: string) {
  return useQuery({
    queryKey: queryKeys.complianceStandard(standard),
    queryFn: () => api.checkCompliance(standard),
    enabled: !!standard,
    staleTime: 300000,
  })
}

// ============ Dashboard Hooks ============

export function useDashboardStats() {
  return useQuery({
    queryKey: queryKeys.dashboard,
    queryFn: async () => {
      // For now, fetch from multiple endpoints and aggregate
      const targets = await api.getTargets()
      const scans = await api.getScans()
      const findings = await api.getFindings()
      
      const activeScans = scans.filter(s => s.status === 'running' || s.status === 'pending').length
      const criticalFindings = findings.findings.filter(f => f.severity === 'Critical').length
      const highFindings = findings.findings.filter(f => f.severity === 'High').length
      const mediumFindings = findings.findings.filter(f => f.severity === 'Medium').length
      const lowFindings = findings.findings.filter(f => f.severity === 'Low').length
      
      return {
        total_scans: scans.length,
        active_scans: activeScans,
        total_findings: findings.total,
        critical_findings: criticalFindings,
        high_findings: highFindings,
        medium_findings: mediumFindings,
        low_findings: lowFindings,
        total_targets: targets.length,
        scans_change: 0, // Would need historical data
        critical_change: 0,
        high_change: 0,
      } as DashboardStats & { total_targets: number }
    },
    staleTime: 30000,
    refetchInterval: 60000, // Auto-refresh every minute
  })
}

// ============ Settings Hooks ============

export function useSettings() {
  return useQuery({
    queryKey: queryKeys.settings,
    queryFn: () => api.getSettings(),
    staleTime: Infinity, // Settings don't change often
  })
}

export function useUpdateSettings() {
  const queryClient = useQueryClient()
  
  return useMutation({
    mutationFn: (data: Partial<Settings>) => api.updateSettings(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.settings })
    },
  })
}