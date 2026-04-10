import type { Finding, Agent, McpServer } from '../types.js'

const SEVERITY_WEIGHTS: Record<string, number> = {
  info: 0,
  low: 5,
  medium: 15,
  high: 30,
  critical: 50,
}

export function calculateScore(
  findings: Finding[],
  _agents: Agent[],
  _mcpServers: McpServer[]
): number {
  const raw = findings.reduce((sum, f) => sum + (SEVERITY_WEIGHTS[f.severity] ?? 0), 0)
  return Math.min(100, raw)
}

export function scoreBand(score: number): string {
  if (score <= 20) return 'Clean'
  if (score <= 40) return 'Caution'
  if (score <= 60) return 'Warning'
  if (score <= 80) return 'Danger'
  return 'Critical'
}
