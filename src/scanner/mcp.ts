import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent, McpServer, Finding, ScanOptions } from '../types.js'

const SHELL_COMMANDS = new Set(['npx', 'node', 'python', 'python3', 'bash', 'sh', 'bun'])

const KNOWN_PACKAGES = new Set([
  '@modelcontextprotocol/server-filesystem',
  '@modelcontextprotocol/server-github',
  '@modelcontextprotocol/server-gitlab',
  '@modelcontextprotocol/server-google-maps',
  '@modelcontextprotocol/server-brave-search',
  '@modelcontextprotocol/server-everything',
  '@modelcontextprotocol/server-memory',
  '@modelcontextprotocol/server-postgres',
  '@modelcontextprotocol/server-puppeteer',
  '@modelcontextprotocol/server-sequential-thinking',
  '@modelcontextprotocol/server-slack',
])

interface McpConfigEntry {
  command?: string
  args?: string[]
  env?: Record<string, string>
  url?: string
}

function isKnownPackage(args: string[] | undefined): boolean {
  if (!args) return false
  return args.some(
    (a) => KNOWN_PACKAGES.has(a) || a.startsWith('@modelcontextprotocol/')
  )
}

function hasShellAccess(command: string | undefined): boolean {
  if (!command) return false
  const base = command.split('/').at(-1) ?? ''
  return SHELL_COMMANDS.has(base)
}

function hasNetworkAccess(command: string | undefined, url: string | undefined): boolean {
  if (url) return true
  if (!command) return false
  return ['http', 'sse', 'fetch'].some((kw) => command.includes(kw))
}

function parseConfigFile(
  filePath: string,
  source: string
): { servers: McpServer[]; findings: Finding[] } {
  const servers: McpServer[] = []
  const findings: Finding[] = []

  try {
    const raw = readFileSync(filePath, 'utf-8')
    const json = JSON.parse(raw) as { mcpServers?: Record<string, McpConfigEntry> }
    const mcpServers = json.mcpServers ?? {}

    for (const [name, cfg] of Object.entries(mcpServers)) {
      const transport = cfg.command ? 'stdio' : cfg.url ? 'http' : 'unknown'
      const shell = hasShellAccess(cfg.command)
      const network = hasNetworkAccess(cfg.command, cfg.url)
      const known = isKnownPackage(cfg.args)
      const hasEnv = cfg.env != null && Object.keys(cfg.env).length > 0

      servers.push({
        name,
        transport,
        command: cfg.command,
        args: cfg.args,
        envVars: cfg.env,
        hasNetworkAccess: network,
        hasShellAccess: shell,
        isKnown: known,
        source,
      })

      if (!known) {
        if (network && shell && hasEnv) {
          findings.push({
            category: 'mcp',
            severity: 'critical',
            title: `Unknown MCP server with full access: ${name}`,
            detail: `${name} (${source}) has network access, shell execution, and env vars`,
            path: filePath,
          })
        } else if (shell) {
          findings.push({
            category: 'mcp',
            severity: 'high',
            title: `Unknown MCP server with shell access: ${name}`,
            detail: `${name} (${source}) can execute shell commands`,
            path: filePath,
          })
        } else {
          findings.push({
            category: 'mcp',
            severity: 'medium',
            title: `Unknown MCP server: ${name}`,
            detail: `${name} (${source}) is not a recognized package`,
            path: filePath,
          })
        }
      }
    }
  } catch {
    // silently skip unreadable or malformed config files
  }

  return { servers, findings }
}

export async function scanMcpServers(
  _agents: Agent[],
  options: ScanOptions
): Promise<{ servers: McpServer[]; findings: Finding[] }> {
  const home = homedir()
  const cwd = options.project ?? process.cwd()

  const configLocations: [string, string][] = [
    [join(home, '.claude', 'claude_desktop_config.json'), 'claude-desktop'],
    [join(home, '.claude.json'), 'claude'],
    [join(home, '.cursor', 'mcp.json'), 'cursor'],
    [join(home, '.windsurf', 'mcp.json'), 'windsurf'],
    [join(cwd, 'mcp.json'), 'project'],
    [join(cwd, '.cursor', 'mcp.json'), 'project-cursor'],
  ]

  const allServers: McpServer[] = []
  const allFindings: Finding[] = []

  for (const [filePath, source] of configLocations) {
    if (!existsSync(filePath)) continue
    const { servers, findings } = parseConfigFile(filePath, source)
    allServers.push(...servers)
    allFindings.push(...findings)
  }

  return { servers: allServers, findings: allFindings }
}
