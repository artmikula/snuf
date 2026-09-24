import { homedir } from 'node:os'
import { resolve } from 'node:path'
import type { ScanResult, ScanOptions, ScanContext } from '../types.js'
import { detectAgents } from './agents.js'
import { scanMcpServers } from './mcp.js'
import { scanSecrets } from './secrets.js'
import { scanPermissions } from './permissions.js'
import { scanShell } from './shell.js'
import { scanRules } from './rules.js'
import { calculateScore, sortFindings } from '../scoring/risk.js'
import { VERSION } from '../version.js'

export async function runScan(options: ScanOptions): Promise<ScanResult> {
  const home = homedir()
  const project = resolve(options.project ?? process.cwd())
  const agents = await detectAgents(home, project, options)
  const ctx: ScanContext = { home, project, agents, options }

  const { servers: mcpServers, findings: mcpFindings } = await scanMcpServers(ctx)
  const { findings: shellFindings, posture } = await scanShell(ctx)
  const secretFindings = await scanSecrets(ctx, mcpServers)
  const unknownStdio = mcpServers.filter((s) => s.transport === 'stdio' && !s.isKnown).length
  const permFindings = await scanPermissions(ctx, posture, unknownStdio)
  const { findings: ruleFindings } = await scanRules(ctx)

  const findings = sortFindings([...secretFindings, ...mcpFindings, ...shellFindings, ...permFindings, ...ruleFindings])

  return {
    version: VERSION,
    agents,
    mcpServers,
    findings,
    score: calculateScore(findings),
    scannedAt: new Date().toISOString(),
    platform: process.platform,
    projectDir: project,
  }
}
