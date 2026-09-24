import type { Finding, ScanResult, Severity, McpServer } from '../types.js'
import { severityRank } from '../scoring/risk.js'

export function visibleFindings(result: ScanResult, minimum?: Severity): Finding[] {
  if (!minimum) return result.findings
  const min = severityRank(minimum)
  return result.findings.filter((f) => severityRank(f.severity) >= min)
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  for (const f of findings) counts[f.severity]++
  return counts
}

export function mcpFlags(server: McpServer): string[] {
  return [
    server.isKnown ? 'trusted publisher' : 'unrecognized',
    server.transport === 'stdio' ? 'local process' : server.transport === 'http' ? 'remote' : 'unknown transport',
    server.hasNetworkAccess ? 'network' : null,
    server.secretKeys.length > 0 ? `${server.secretKeys.length} credential${server.secretKeys.length > 1 ? 's' : ''}` : null,
  ].filter((x): x is string => x !== null)
}

export function recommendations(result: ScanResult): string[] {
  const recs: string[] = []
  const has = (pred: (f: Finding) => boolean) => result.findings.some(pred)

  if (has((f) => f.category === 'secret' && f.title.includes('MCP config'))) {
    recs.push('Move credentials out of MCP config files. Reference them by name (${VAR}) or use the agent keychain.')
  }
  if (has((f) => f.category === 'secret' && f.title.includes('shell environment'))) {
    recs.push('Stop exporting API keys in your shell profile. Use per project env files or direnv.')
  }
  if (has((f) => f.category === 'shell' && (f.title.includes('without permission prompts') || f.title.includes('every shell command') || f.title.includes('never asks') || f.title.includes('YOLO')))) {
    recs.push('Turn permission prompts back on. Bypass mode makes prompt injection a remote shell.')
  }
  const unknown = result.mcpServers.filter((s) => s.transport === 'stdio' && !s.isKnown)
  if (unknown.length > 0) {
    recs.push(`Review ${unknown.length} unrecognized MCP server${unknown.length > 1 ? 's' : ''}: ${unknown.slice(0, 4).map((s) => s.name).join(', ')}${unknown.length > 4 ? ', ...' : ''}`)
  }
  if (has((f) => f.category === 'file-access' && f.title.includes('home directory'))) {
    recs.push('Start agents inside a repository, never from your home directory.')
  }
  if (has((f) => f.title === 'Claude Code has no deny rules')) {
    recs.push('Add deny rules for .env, ~/.ssh, ~/.aws and other credential paths in ~/.claude/settings.json.')
  }
  if (has((f) => f.category === 'rules' && f.severity !== 'info')) {
    recs.push('Read the flagged rules and skill files. They run before anything you type.')
  }
  if (has((f) => f.category === 'secret' && f.title.includes('plaintext'))) {
    recs.push('Treat agent credential stores like SSH keys. Lock down file permissions and rotate tokens after any suspicious package install.')
  }
  if (recs.length === 0 && result.agents.length > 0) {
    recs.push('Nothing urgent. Re-run snuf after installing any new MCP server or plugin.')
  }
  return recs
}
