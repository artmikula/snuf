import chalk from 'chalk'
import boxen from 'boxen'
import type { ScanResult, ScanOptions, Finding, Severity } from '../types.js'
import { scoreBand } from '../scoring/risk.js'
import { visibleFindings, countBySeverity, mcpFlags, recommendations } from './shared.js'

function tone(score: number): 'green' | 'yellow' | 'red' {
  if (score <= 20) return 'green'
  if (score <= 60) return 'yellow'
  return 'red'
}

const COLOR: Record<Severity, (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.blue,
  info: chalk.gray,
}

const TAG: Record<Severity, string> = {
  critical: ' CRIT ',
  high: ' HIGH ',
  medium: ' MED  ',
  low: ' LOW  ',
  info: ' INFO ',
}

function tree(index: number, total: number): string {
  return index === total - 1 ? '  └─' : '  ├─'
}

function short(f: Finding, home: string): string {
  if (!f.path) return ''
  const p = f.path.replace(home, '~')
  return f.title.includes(p) ? '' : chalk.gray(` ${p}`)
}

function block(title: string, findings: Finding[], home: string, out: string[]): void {
  if (findings.length === 0) return
  out.push(chalk.bold(title))
  findings.forEach((f, i) => {
    out.push(`${tree(i, findings.length)} ${COLOR[f.severity](TAG[f.severity])} ${f.title}${short(f, home)}`)
  })
  out.push('')
}

export function renderTerminal(result: ScanResult, options: ScanOptions, home: string): string {
  const band = scoreBand(result.score)
  if (options.quick) return `${result.score}/100 ${band}`

  const counts = countBySeverity(result.findings)
  const findings = visibleFindings(result, options.severity)
  const out: string[] = []
  const color = tone(result.score)
  const scoreText = chalk[color].bold(`${result.score}/100  ${band.toUpperCase()}`)
  const summary = chalk.gray(`${counts.critical} critical · ${counts.high} high · ${counts.medium} medium · ${counts.low} low`)

  out.push(boxen(`${chalk.bold('snuf')}  what your AI agents can reach\n\nScore  ${scoreText}\n${summary}`, { padding: 1, borderStyle: 'round', borderColor: color }))
  out.push('')

  out.push(chalk.bold(`🔍 Agents: ${result.agents.length}`))
  if (result.agents.length === 0) out.push(chalk.gray('  └─ none found'))
  result.agents.forEach((a, i) => {
    const status = a.running ? chalk.green('running') : chalk.gray('installed')
    out.push(`${tree(i, result.agents.length)} ${a.name}${a.version ? chalk.gray(` v${a.version}`) : ''}  ${status}`)
  })
  out.push('')

  out.push(chalk.bold(`🔌 MCP servers: ${result.mcpServers.length}`))
  if (result.mcpServers.length === 0) out.push(chalk.gray('  └─ none configured'))
  result.mcpServers.forEach((s, i) => {
    const icon = s.secretKeys.length > 0 ? '🔴' : s.isKnown ? '✅' : '⚠️ '
    out.push(`${tree(i, result.mcpServers.length)} ${icon} ${s.name} ${chalk.gray(`(${mcpFlags(s).join(', ')}) ${s.source}`)}`)
  })
  out.push('')

  block(`🔑 Secrets`, findings.filter((f) => f.category === 'secret'), home, out)
  block(`🛠  Shell and permissions`, findings.filter((f) => f.category === 'shell'), home, out)
  block(`📁 File access`, findings.filter((f) => f.category === 'file-access'), home, out)
  block(`🔌 MCP findings`, findings.filter((f) => f.category === 'mcp'), home, out)
  block(`📜 Rules and skills`, findings.filter((f) => f.category === 'rules'), home, out)

  if (findings.length === 0) {
    out.push(chalk.gray(options.severity ? `No findings at ${options.severity} or above.` : 'No findings.'))
    out.push('')
  }

  const recs = recommendations(result)
  if (recs.length > 0) {
    out.push(chalk.bold('🛡️  Do this first'))
    recs.slice(0, 5).forEach((r, i) => out.push(`  ${i + 1}. ${r}`))
    out.push('')
  }
  out.push(chalk.gray(`Details: snuf --format markdown --output snuf-report.md   ·   Full JSON: snuf --format json`))
  return out.join('\n')
}
