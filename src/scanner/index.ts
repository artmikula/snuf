import type { ScanResult, ScanOptions } from '../types.js'
import { detectAgents } from './agents.js'
import { scanMcpServers } from './mcp.js'
import { scanSecrets } from './secrets.js'
import { scanPermissions } from './permissions.js'
import { scanShell } from './shell.js'
import { calculateScore } from '../scoring/risk.js'

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const agents = await detectAgents(options)
  const { servers: mcpServers, findings: mcpFindings } = await scanMcpServers(agents, options)
  const secretFindings = await scanSecrets(agents, mcpServers)
  const permFindings = await scanPermissions(agents)
  const shellFindings = await scanShell(agents)

  const findings = [...mcpFindings, ...secretFindings, ...permFindings, ...shellFindings]
  const score = calculateScore(findings, agents, mcpServers)

  return {
    agents,
    mcpServers,
    findings,
    score,
    scannedAt: new Date().toISOString(),
    platform: process.platform,
  }
}
