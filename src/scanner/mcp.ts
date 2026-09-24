import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { McpServer, Finding, ScanContext } from '../types.js'
import { readJson, readText, parseTomlSubset } from './config-parsers.js'
import { classifySecret, mask } from './secret-patterns.js'

const TRUSTED_SCOPES = [
  '@modelcontextprotocol/',
  '@anthropic-ai/',
  '@anthropic/',
  '@playwright/',
  '@upstash/',
  '@notionhq/',
  '@supabase/',
  '@sentry/',
  '@stripe/',
  '@cloudflare/',
  '@vercel/',
  '@github/',
  '@huggingface/',
  '@aws/',
  '@awslabs/',
  '@azure/',
  '@google/',
  '@googlemaps/',
  '@microsoft/',
  '@elastic/',
  '@atlassian/',
  '@linear/',
  '@figma/',
  '@browserbasehq/',
  '@hubspot/',
  '@mongodb-js/',
  '@neondatabase/',
  '@prisma/',
  '@shopify/',
  '@postman/',
  '@apify/',
  '@e2b/',
  '@openai/',
  '@slack/',
  '@datadog/',
  '@pinecone-database/',
  '@browserstack/',
  '@heroku/',
  '@netlify/',
  '@railway/',
  '@21st-dev/',
  '@chroma-core/',
  '@zapier/',
]

const TRUSTED_PACKAGES = new Set([
  'mcp-remote',
  'firecrawl-mcp',
  'tavily-mcp',
  'chrome-devtools-mcp',
  'mcp-server-fetch',
  'mcp-server-git',
  'mcp-server-time',
  'mcp-server-sqlite',
  'github-mcp-server',
  'exa-mcp-server',
  'perplexity-mcp',
  'server-perplexity-ask',
  'graphlit-mcp-server',
  'obsidian-mcp',
  'mcp-obsidian',
  'mcp-atlassian',
  'docker-mcp',
  'awslabs.aws-documentation-mcp-server',
  'mcp-server-docker',
])

const CODE_RUNNERS = new Set([
  'npx', 'bunx', 'pnpx', 'pnpm', 'yarn', 'npm', 'node', 'bun', 'deno',
  'uvx', 'uv', 'pipx', 'python', 'python3', 'py',
  'bash', 'sh', 'zsh', 'cmd', 'cmd.exe', 'powershell', 'pwsh',
  'docker', 'podman', 'ruby', 'go', 'cargo', 'java', 'dotnet',
])

const URL_RE = /https?:\/\//i

interface RawServer {
  name: string
  command?: string
  args?: string[]
  env?: Record<string, unknown>
  headers?: Record<string, unknown>
  url?: string
}

interface ConfigSource {
  path: string
  agent: string
  label: string
  parse: (path: string) => RawServer[]
}

function asRecord(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined
}

function asStringArray(v: unknown): string[] | undefined {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : undefined
}

function fromEntry(name: string, entry: unknown): RawServer | undefined {
  const cfg = asRecord(entry)
  if (!cfg) return undefined
  let command = typeof cfg['command'] === 'string' ? (cfg['command'] as string) : undefined
  let args = asStringArray(cfg['args'])
  if (Array.isArray(cfg['command'])) {
    const parts = asStringArray(cfg['command']) ?? []
    command = parts[0]
    args = parts.slice(1)
  }
  const url =
    typeof cfg['url'] === 'string'
      ? (cfg['url'] as string)
      : typeof cfg['serverUrl'] === 'string'
        ? (cfg['serverUrl'] as string)
        : typeof cfg['httpUrl'] === 'string'
          ? (cfg['httpUrl'] as string)
          : undefined
  return {
    name,
    command,
    args,
    url,
    env: asRecord(cfg['env']) ?? asRecord(cfg['environment']),
    headers: asRecord(cfg['headers']),
  }
}

function fromMap(map: unknown): RawServer[] {
  const rec = asRecord(map)
  if (!rec) return []
  return Object.entries(rec)
    .map(([name, entry]) => fromEntry(name, entry))
    .filter((s): s is RawServer => s !== undefined)
}

const jsonKey =
  (...keys: string[]) =>
  (path: string): RawServer[] => {
    const json = asRecord(readJson(path))
    if (!json) return []
    let node: unknown = json
    for (const key of keys) {
      node = asRecord(node)?.[key]
      if (node === undefined) return []
    }
    return fromMap(node)
  }

function claudeUserConfig(path: string): RawServer[] {
  const json = asRecord(readJson(path))
  if (!json) return []
  const servers = fromMap(json['mcpServers'])
  const projects = asRecord(json['projects'])
  if (projects) {
    for (const [projectPath, project] of Object.entries(projects)) {
      for (const s of fromMap(asRecord(project)?.['mcpServers'])) {
        servers.push({ ...s, name: `${s.name} (${projectPath})` })
      }
    }
  }
  return servers
}

function tomlServers(path: string): RawServer[] {
  const text = readText(path)
  if (text === undefined) return []
  const toml = parseTomlSubset(text)
  return fromMap(toml['mcp_servers'])
}

function ampSettings(path: string): RawServer[] {
  const json = asRecord(readJson(path))
  if (!json) return []
  return fromMap(json['amp.mcpServers'] ?? asRecord(json['amp'])?.['mcpServers'])
}

function zedSettings(path: string): RawServer[] {
  const json = asRecord(readJson(path))
  if (!json) return []
  const servers: RawServer[] = []
  for (const [name, entry] of Object.entries(asRecord(json['context_servers']) ?? {})) {
    const cfg = asRecord(entry)
    if (!cfg) continue
    const inner = asRecord(cfg['command'])
    if (inner) {
      servers.push({
        name,
        command: typeof inner['path'] === 'string' ? (inner['path'] as string) : undefined,
        args: asStringArray(inner['args']),
        env: asRecord(inner['env']),
      })
      continue
    }
    const s = fromEntry(name, entry)
    if (s) servers.push(s)
  }
  return servers
}

function gooseConfig(path: string): RawServer[] {
  const text = readText(path)
  if (text === undefined) return []
  const servers: RawServer[] = []
  let current: RawServer | undefined
  let inEnvs = false
  for (const rawLine of text.split('\n')) {
    const indent = rawLine.search(/\S/)
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    if (indent === 2 && line.endsWith(':')) {
      current = { name: line.slice(0, -1), env: {} }
      servers.push(current)
      inEnvs = false
      continue
    }
    if (!current) continue
    if (indent === 4) {
      inEnvs = line === 'envs:'
      const m = line.match(/^(cmd|uri|url):\s*(.+)$/)
      if (m) {
        const value = m[2]!.replace(/^["']|["']$/g, '')
        if (m[1] === 'cmd') current.command = value
        else current.url = value
      }
      const argsMatch = line.match(/^args:\s*\[(.*)\]$/)
      if (argsMatch) {
        current.args = argsMatch[1]!.split(',').map((a) => a.trim().replace(/^["']|["']$/g, '')).filter(Boolean)
      }
      continue
    }
    if (indent === 6 && inEnvs) {
      const m = line.match(/^([^:]+):\s*(.*)$/)
      if (m && current.env) current.env[m[1]!.trim()] = m[2]!.replace(/^["']|["']$/g, '')
    }
  }
  return servers.filter((s) => s.command || s.url)
}

function appSupport(home: string): string {
  if (process.platform === 'darwin') return join(home, 'Library', 'Application Support')
  if (process.platform === 'win32') return process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming')
  return join(home, '.config')
}

function vscodeUser(home: string): string {
  return process.platform === 'linux'
    ? join(home, '.config', 'Code', 'User')
    : join(appSupport(home), 'Code', 'User')
}

export function mcpConfigSources(home: string, project: string): ConfigSource[] {
  const mcpServers = jsonKey('mcpServers')
  const vscodeStyle = jsonKey('servers')
  const clineStorage = join(vscodeUser(home), 'globalStorage')
  return [
    { path: join(home, '.claude.json'), agent: 'claude-code', label: '~/.claude.json', parse: claudeUserConfig },
    { path: join(project, '.mcp.json'), agent: 'claude-code', label: 'project .mcp.json', parse: mcpServers },
    { path: join(appSupport(home), 'Claude', 'claude_desktop_config.json'), agent: 'claude-desktop', label: 'Claude Desktop', parse: mcpServers },
    { path: join(home, '.config', 'Claude', 'claude_desktop_config.json'), agent: 'claude-desktop', label: 'Claude Desktop', parse: mcpServers },
    { path: join(home, '.cursor', 'mcp.json'), agent: 'cursor', label: '~/.cursor/mcp.json', parse: mcpServers },
    { path: join(project, '.cursor', 'mcp.json'), agent: 'cursor', label: 'project .cursor/mcp.json', parse: mcpServers },
    { path: join(home, '.codeium', 'windsurf', 'mcp_config.json'), agent: 'windsurf', label: 'Windsurf', parse: mcpServers },
    { path: join(project, '.windsurf', 'mcp.json'), agent: 'windsurf', label: 'project .windsurf/mcp.json', parse: mcpServers },
    { path: join(home, '.copilot', 'mcp-config.json'), agent: 'copilot', label: 'Copilot CLI', parse: mcpServers },
    { path: join(project, '.github', 'mcp.json'), agent: 'copilot', label: 'project .github/mcp.json', parse: mcpServers },
    { path: join(vscodeUser(home), 'mcp.json'), agent: 'copilot', label: 'VS Code user mcp.json', parse: vscodeStyle },
    { path: join(project, '.vscode', 'mcp.json'), agent: 'copilot', label: 'project .vscode/mcp.json', parse: vscodeStyle },
    { path: join(home, '.codex', 'config.toml'), agent: 'codex', label: '~/.codex/config.toml', parse: tomlServers },
    { path: join(project, '.codex', 'config.toml'), agent: 'codex', label: 'project .codex/config.toml', parse: tomlServers },
    { path: join(home, '.gemini', 'settings.json'), agent: 'gemini-cli', label: '~/.gemini/settings.json', parse: mcpServers },
    { path: join(project, '.gemini', 'settings.json'), agent: 'gemini-cli', label: 'project .gemini/settings.json', parse: mcpServers },
    { path: join(home, '.gemini', 'antigravity', 'mcp_config.json'), agent: 'antigravity', label: 'Antigravity', parse: mcpServers },
    { path: join(home, '.config', 'opencode', 'opencode.json'), agent: 'opencode', label: '~/.config/opencode/opencode.json', parse: jsonKey('mcp') },
    { path: join(project, 'opencode.json'), agent: 'opencode', label: 'project opencode.json', parse: jsonKey('mcp') },
    { path: join(home, '.openclaw', 'openclaw.json'), agent: 'openclaw', label: '~/.openclaw/openclaw.json', parse: mcpServers },
    { path: join(home, '.openclaw', 'mcp.json'), agent: 'openclaw', label: '~/.openclaw/mcp.json', parse: mcpServers },
    { path: join(home, '.kiro', 'settings', 'mcp.json'), agent: 'kiro', label: '~/.kiro/settings/mcp.json', parse: mcpServers },
    { path: join(project, '.kiro', 'settings', 'mcp.json'), agent: 'kiro', label: 'project .kiro/settings/mcp.json', parse: mcpServers },
    { path: join(home, '.config', 'amp', 'settings.json'), agent: 'amp', label: 'Amp settings', parse: ampSettings },
    { path: join(clineStorage, 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), agent: 'cline', label: 'Cline', parse: mcpServers },
    { path: join(home, '.cline', 'mcp.json'), agent: 'cline', label: '~/.cline/mcp.json', parse: mcpServers },
    { path: join(clineStorage, 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), agent: 'roo-code', label: 'Roo Code', parse: mcpServers },
    { path: join(project, '.roo', 'mcp.json'), agent: 'roo-code', label: 'project .roo/mcp.json', parse: mcpServers },
    { path: join(home, '.config', 'zed', 'settings.json'), agent: 'zed', label: 'Zed settings', parse: zedSettings },
    { path: join(project, '.zed', 'settings.json'), agent: 'zed', label: 'project .zed/settings.json', parse: zedSettings },
    { path: join(home, '.config', 'goose', 'config.yaml'), agent: 'goose', label: 'Goose config', parse: gooseConfig },
    { path: join(home, '.junie', 'mcp', 'mcp.json'), agent: 'junie', label: '~/.junie/mcp/mcp.json', parse: mcpServers },
    { path: join(project, '.junie', 'mcp', 'mcp.json'), agent: 'junie', label: 'project .junie/mcp/mcp.json', parse: mcpServers },
    { path: join(appSupport(home), 'Trae', 'mcp.json'), agent: 'trae', label: 'Trae', parse: mcpServers },
    { path: join(project, '.trae', 'mcp.json'), agent: 'trae', label: 'project .trae/mcp.json', parse: mcpServers },
    { path: join(home, '.factory', 'mcp.json'), agent: 'factory', label: 'Factory Droid', parse: mcpServers },
    { path: join(home, '.qwen', 'settings.json'), agent: 'qwen-code', label: '~/.qwen/settings.json', parse: mcpServers },
    { path: join(project, '.qwen', 'settings.json'), agent: 'qwen-code', label: 'project .qwen/settings.json', parse: mcpServers },
    { path: join(home, '.aws', 'amazonq', 'mcp.json'), agent: 'amazon-q', label: 'Amazon Q', parse: mcpServers },
    { path: join(project, '.amazonq', 'mcp.json'), agent: 'amazon-q', label: 'project .amazonq/mcp.json', parse: mcpServers },
    { path: join(project, '.warp', '.mcp.json'), agent: 'warp', label: 'project .warp/.mcp.json', parse: mcpServers },
    { path: join(home, '.vibe', 'config.toml'), agent: 'vibe', label: 'Mistral Vibe', parse: tomlServers },
    { path: join(home, '.continue', 'config.json'), agent: 'continue', label: '~/.continue/config.json', parse: jsonKey('experimental', 'modelContextProtocolServers') },
    { path: join(project, 'mcp.json'), agent: 'project', label: 'project mcp.json', parse: mcpServers },
  ]
}

function packageName(command: string | undefined, args: string[] | undefined): string | undefined {
  const base = command?.split(/[\\/]/).at(-1)?.toLowerCase()
  if (!base || !args) return undefined
  if (['npx', 'bunx', 'pnpx', 'uvx', 'pipx', 'pnpm', 'yarn'].includes(base)) {
    const positional = args.filter((a) => !a.startsWith('-') && a !== 'dlx' && a !== 'exec' && a !== 'run')
    const pkg = positional[0]
    return pkg?.replace(/@[\d^~][^/]*$/, '').replace(/@latest$/, '')
  }
  if (base === 'docker' || base === 'podman') {
    const runIdx = args.indexOf('run')
    if (runIdx === -1) return undefined
    const positional = args.slice(runIdx + 1).filter((a) => !a.startsWith('-'))
    return positional[0]
  }
  return undefined
}

function isTrusted(command: string | undefined, args: string[] | undefined, url: string | undefined): boolean {
  if (url && !command) return true
  const pkg = packageName(command, args)
  if (!pkg) return false
  if (TRUSTED_PACKAGES.has(pkg)) return true
  return TRUSTED_SCOPES.some((scope) => pkg.startsWith(scope))
}

function runsLocalCode(command: string | undefined): boolean {
  if (!command) return false
  const base = command.split(/[\\/]/).at(-1)?.toLowerCase() ?? ''
  return CODE_RUNNERS.has(base) || base.endsWith('.sh') || base.endsWith('.py') || base.endsWith('.js')
}

function reachesNetwork(raw: RawServer): boolean {
  if (raw.url) return true
  const all = [raw.command ?? '', ...(raw.args ?? [])]
  if (all.some((a) => URL_RE.test(a))) return true
  const pkg = packageName(raw.command, raw.args) ?? ''
  return /remote|fetch|http|sse|browser|puppeteer|playwright|search|web|crawl|slack|github|gitlab|jira|notion|linear/i.test(pkg)
}

function stringRecord(rec: Record<string, unknown> | undefined): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(rec ?? {})) {
    if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[k] = String(v)
  }
  return out
}

function toServer(raw: RawServer, source: ConfigSource): McpServer {
  const env = stringRecord(raw.env)
  const headers = stringRecord(raw.headers)
  const secretKeys: string[] = []
  for (const [k, v] of Object.entries(env)) {
    if (v.startsWith('${') || v.startsWith('$')) continue
    if (classifySecret(k, v)) secretKeys.push(k)
  }
  for (const [k, v] of Object.entries(headers)) {
    if (v.startsWith('${') || v.startsWith('$')) continue
    if (/^(authorization|x-api-key|api-key|apikey|x-auth-token|x-token|cookie)$/i.test(k) || classifySecret(k, v)) {
      secretKeys.push(`header:${k}`)
    }
  }
  const stdio = Boolean(raw.command)
  return {
    name: raw.name,
    agent: source.agent,
    transport: stdio ? 'stdio' : raw.url ? 'http' : 'unknown',
    command: raw.command,
    args: raw.args,
    url: raw.url,
    envVars: Object.keys(env).length ? Object.fromEntries(Object.entries(env).map(([k, v]) => [k, mask(v)])) : undefined,
    headers: Object.keys(headers).length ? Object.fromEntries(Object.entries(headers).map(([k, v]) => [k, mask(v)])) : undefined,
    secretKeys,
    hasNetworkAccess: reachesNetwork(raw),
    hasShellAccess: stdio && runsLocalCode(raw.command),
    isKnown: isTrusted(raw.command, raw.args, raw.url),
    source: source.label,
  }
}

function findingsFor(server: McpServer, path: string): Finding[] {
  const findings: Finding[] = []
  const pkg = packageName(server.command, server.args)
  const what = pkg ?? server.command ?? server.url ?? 'unknown'
  if (server.transport === 'stdio' && !server.isKnown) {
    const hasSecrets = server.secretKeys.length > 0
    if (hasSecrets && server.hasNetworkAccess) {
      findings.push({
        category: 'mcp',
        severity: 'high',
        title: `Unrecognized MCP server holds credentials and reaches the network: ${server.name}`,
        detail: `${what} runs as a local process with ${server.secretKeys.length} credential(s) in its env and can make network requests. Anything it does with those credentials is invisible to you. Source: ${server.source}`,
        path,
        agent: server.agent,
      })
    } else if (hasSecrets) {
      findings.push({
        category: 'mcp',
        severity: 'high',
        title: `Unrecognized MCP server holds credentials: ${server.name}`,
        detail: `${what} runs as a local process with ${server.secretKeys.length} credential(s) passed in its env. Source: ${server.source}`,
        path,
        agent: server.agent,
      })
    } else {
      findings.push({
        category: 'mcp',
        severity: 'medium',
        title: `Unrecognized MCP server runs local code: ${server.name}`,
        detail: `${what} is not on the trusted publisher list. It runs with your user permissions and full environment, without a prompt. Source: ${server.source}`,
        path,
        agent: server.agent,
      })
    }
  }
  if (server.transport === 'http' && server.url && server.url.startsWith('http://') && !/localhost|127\.0\.0\.1|\[::1\]/.test(server.url)) {
    findings.push({
      category: 'mcp',
      severity: 'medium',
      title: `MCP server over plain HTTP: ${server.name}`,
      detail: `${server.url} is not encrypted. Tool calls and any auth headers travel in cleartext. Source: ${server.source}`,
      path,
      agent: server.agent,
    })
  }
  return findings
}

export async function scanMcpServers(
  ctx: ScanContext
): Promise<{ servers: McpServer[]; findings: Finding[] }> {
  const servers: McpServer[] = []
  const findings: Finding[] = []
  const seen = new Set<string>()

  for (const source of mcpConfigSources(ctx.home, ctx.project)) {
    if (ctx.options.agent && source.agent !== ctx.options.agent && source.agent !== 'project') continue
    if (seen.has(source.path) || !existsSync(source.path)) continue
    seen.add(source.path)
    for (const raw of source.parse(source.path)) {
      const server = toServer(raw, source)
      servers.push(server)
      findings.push(...findingsFor(server, source.path))
    }
  }

  return { servers, findings }
}
