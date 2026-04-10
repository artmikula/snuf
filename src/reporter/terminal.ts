import chalk from 'chalk'
import boxen from 'boxen'
import type { ScanResult, ScanOptions, McpServer, Finding } from '../types.js'
import { scoreBand } from '../scoring/risk.js'

type ChalkColor = 'green' | 'yellow' | 'red'

function scoreBorderColor(score: number): ChalkColor {
  if (score <= 20) return 'green'
  if (score <= 60) return 'yellow'
  return 'red'
}

function scoreLabel(score: number): string {
  const band = scoreBand(score)
  if (score <= 20) return chalk.green(`${score}/100  ${band}`)
  if (score <= 60) return chalk.yellow(`${score}/100  ${band}`)
  return chalk.red.bold(`${score}/100  ${band}`)
}

function mcpIcon(server: McpServer): string {
  if (server.isKnown) return '✅'
  if (!server.isKnown && server.hasNetworkAccess && server.hasShellAccess) return '🔴'
  return '⚠️ '
}

function severityColor(severity: Finding['severity']): (s: string) => string {
  const map: Record<string, (s: string) => string> = {
    critical: chalk.red.bold,
    high: chalk.red,
    medium: chalk.yellow,
    low: chalk.gray,
    info: chalk.gray,
  }
  return map[severity] ?? chalk.gray
}

function treePrefix(index: number, total: number): string {
  return index === total - 1 ? '  └──' : '  ├──'
}

function generateRecommendations(result: ScanResult): string[] {
  const recs: string[] = []

  const criticalMcp = result.mcpServers.filter(
    (s) => !s.isKnown && s.hasNetworkAccess && s.hasShellAccess
  )
  if (criticalMcp.length > 0) {
    recs.push(
      `Audit unknown MCP server${criticalMcp.length > 1 ? 's' : ''}: ${criticalMcp.map((s) => s.name).join(', ')}`
    )
  }

  const mcpWithEnv = result.mcpServers.filter(
    (s) => s.envVars && Object.keys(s.envVars).length > 0
  )
  if (mcpWithEnv.length > 0) {
    recs.push('Move API keys from MCP configs to a secrets manager')
  }

  const criticalFindings = result.findings.filter((f) => f.severity === 'critical')
  if (criticalFindings.length > 0 && !recs.some((r) => r.includes('API keys'))) {
    recs.push(
      `Address ${criticalFindings.length} critical finding${criticalFindings.length > 1 ? 's' : ''} immediately`
    )
  }

  if (result.agents.length > 4) {
    recs.push('Consider removing unused AI agents to reduce attack surface')
  }

  recs.push('Save a full report: snuf --format markdown --output report.md')

  return recs
}

export function renderTerminal(result: ScanResult, options: ScanOptions): void {
  if (options.quick) {
    console.log(`Score: ${result.score}/100 — ${scoreBand(result.score)}`)
    return
  }

  const header = `snuf — AI Agent Security Report\nScore: ${scoreLabel(result.score)}`
  console.log(
    boxen(header, {
      padding: 1,
      borderStyle: 'round',
      borderColor: scoreBorderColor(result.score),
    })
  )
  console.log()

  // Agents
  console.log(chalk.bold(`🔍 Agents Found: ${result.agents.length}`))
  if (result.agents.length === 0) {
    console.log(chalk.gray('  └── none found'))
  } else {
    result.agents.forEach((agent, i) => {
      const prefix = treePrefix(i, result.agents.length)
      const status = agent.running
        ? chalk.green('✓ running')
        : chalk.gray('○ not running')
      const version = agent.version ? ` v${agent.version}` : ''
      console.log(`${prefix} ${agent.name}${version} ${status}`)
    })
  }
  console.log()

  // MCP servers
  console.log(chalk.bold(`🔌 MCP Servers: ${result.mcpServers.length}`))
  if (result.mcpServers.length === 0) {
    console.log(chalk.gray('  └── none found'))
  } else {
    result.mcpServers.forEach((server, i) => {
      const prefix = treePrefix(i, result.mcpServers.length)
      const icon = mcpIcon(server)
      const flags = [
        !server.isKnown ? 'unknown' : null,
        server.hasShellAccess ? 'shell' : null,
        server.hasNetworkAccess ? 'network' : null,
        server.envVars && Object.keys(server.envVars).length > 0 ? 'env vars' : null,
      ]
        .filter(Boolean)
        .join(', ')
      const detail = flags ? ` (${flags})` : ''
      console.log(`${prefix} ${icon} ${server.name}${detail}`)
    })
  }
  console.log()

  // Findings filtered by --severity
  const severityOrder: Finding['severity'][] = ['critical', 'high', 'medium', 'low', 'info']
  const minIdx = options.severity
    ? severityOrder.indexOf(options.severity as Finding['severity'])
    : severityOrder.length - 1
  const visibleFindings = result.findings.filter(
    (f) => severityOrder.indexOf(f.severity) <= minIdx
  )

  if (visibleFindings.length > 0) {
    console.log(chalk.bold(`⚠️  Findings: ${visibleFindings.length}`))
    visibleFindings.forEach((finding, i) => {
      const prefix = treePrefix(i, visibleFindings.length)
      const color = severityColor(finding.severity)
      console.log(`${prefix} ${color(`[${finding.severity.toUpperCase()}]`)} ${finding.title}`)
    })
    console.log()
  }

  // Recommendations
  const recs = generateRecommendations(result)
  if (recs.length > 0) {
    console.log(chalk.bold('🛡️  Top Recommendations:'))
    recs.slice(0, 3).forEach((rec, i) => {
      console.log(`  ${i + 1}. ${rec}`)
    })
    console.log()
  }
}
