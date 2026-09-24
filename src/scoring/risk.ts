import type { Finding, Severity } from '../types.js'

const WEIGHTS: Record<Severity, number> = {
  info: 0,
  low: 0.03,
  medium: 0.09,
  high: 0.2,
  critical: 0.38,
}

export function calculateScore(findings: Finding[]): number {
  const survival = findings.reduce((acc, f) => acc * (1 - (WEIGHTS[f.severity] ?? 0)), 1)
  return Math.round((1 - survival) * 100)
}

export function scoreBand(score: number): string {
  if (score <= 20) return 'Clean'
  if (score <= 40) return 'Caution'
  if (score <= 60) return 'Warning'
  if (score <= 80) return 'Danger'
  return 'Critical'
}

export function severityRank(severity: Severity): number {
  return ['info', 'low', 'medium', 'high', 'critical'].indexOf(severity)
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => severityRank(b.severity) - severityRank(a.severity))
}
