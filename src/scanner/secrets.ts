import { existsSync } from 'node:fs'
import fg from 'fast-glob'
import { join } from 'node:path'
import type { Finding, McpServer, ScanContext } from '../types.js'
import { readJson, readText, parseEnvFile, walkStrings, isTrackedInGit } from './config-parsers.js'
import { classifySecret, classifyValue } from './secret-patterns.js'

interface CredentialStore {
  path: string
  agent: string
  label: string
}

function credentialStores(home: string): CredentialStore[] {
  const local = process.platform === 'win32' ? join(home, 'AppData', 'Local') : join(home, '.local', 'share')
  return [
    { path: join(home, '.claude', '.credentials.json'), agent: 'claude-code', label: 'Claude Code OAuth credentials' },
    { path: join(home, '.codex', 'auth.json'), agent: 'codex', label: 'Codex CLI auth tokens' },
    { path: join(home, '.gemini', 'oauth_creds.json'), agent: 'gemini-cli', label: 'Gemini CLI OAuth credentials' },
    { path: join(home, '.config', 'github-copilot', 'hosts.json'), agent: 'copilot', label: 'GitHub Copilot OAuth token' },
    { path: join(home, '.config', 'github-copilot', 'apps.json'), agent: 'copilot', label: 'GitHub Copilot OAuth token' },
    { path: join(local, 'opencode', 'auth.json'), agent: 'opencode', label: 'OpenCode auth tokens' },
    { path: join(home, '.openclaw', 'credentials'), agent: 'openclaw', label: 'OpenClaw credential store' },
    { path: join(home, '.qwen', 'oauth_creds.json'), agent: 'qwen-code', label: 'Qwen Code OAuth credentials' },
    { path: join(home, '.copilot', 'config.json'), agent: 'copilot', label: 'Copilot CLI token fallback' },
    { path: join(home, '.hermes', '.env'), agent: 'hermes', label: 'Hermes Agent secrets file' },
    { path: join(home, '.factory', 'config.json'), agent: 'factory', label: 'Factory Droid BYOK keys' },
    { path: join(home, '.kimi-code', 'auth.json'), agent: 'kimi-code', label: 'Kimi Code auth tokens' },
    { path: join(home, '.grok', 'auth.json'), agent: 'grok', label: 'Grok Build auth tokens' },
  ]
}

function stateFiles(home: string): CredentialStore[] {
  return [
    { path: join(home, '.claude.json'), agent: 'claude-code', label: '~/.claude.json' },
    { path: join(home, '.openclaw', 'openclaw.json'), agent: 'openclaw', label: '~/.openclaw/openclaw.json' },
    { path: join(home, '.config', 'amp', 'settings.json'), agent: 'amp', label: 'Amp settings' },
    { path: join(home, '.continue', 'config.json'), agent: 'continue', label: 'Continue config' },
    { path: join(home, '.config', 'zed', 'settings.json'), agent: 'zed', label: 'Zed settings' },
    { path: join(home, '.factory', 'settings.json'), agent: 'factory', label: 'Factory Droid settings' },
    { path: join(home, '.pi', 'agent', 'settings.json'), agent: 'pi', label: 'Pi settings' },
  ]
}

function mcpSecretFindings(servers: McpServer[], project: string): Finding[] {
  const findings: Finding[] = []
  const committed = new Map<string, string[]>()
  for (const server of servers) {
    if (server.secretKeys.length > 0 && isTrackedInGit(project, server.sourcePath)) {
      committed.set(server.sourcePath, [...(committed.get(server.sourcePath) ?? []), ...server.secretKeys.map((k) => k.replace(/^header:/, ''))])
    }
    for (const key of server.secretKeys) {
      const isHeader = key.startsWith('header:')
      const name = isHeader ? key.slice(7) : key
      findings.push({
        category: 'secret',
        severity: 'critical',
        title: `${name} stored in plaintext in MCP config (${server.name})`,
        detail: isHeader
          ? `The ${name} header for "${server.name}" is written into ${server.source}. Every agent and MCP server that reads this file gets it.`
          : `${name} is passed to "${server.name}" through ${server.source}. Every agent and MCP server that reads this file gets it, and the server process receives it in the clear.`,
        agent: server.agent,
      })
    }
  }
  for (const [path, keys] of committed) {
    findings.push({
      category: 'secret',
      severity: 'critical',
      title: `MCP config with ${keys.length} credential${keys.length > 1 ? 's' : ''} is committed to git`,
      detail: `${path.replace(project, '.')} is tracked by this repository and holds ${keys.join(', ')}. If the remote is public, or ever becomes public, these are leaked. GitGuardian found 24,008 secrets in public MCP config files in 2026. Remove the values, rotate them, and purge the history.`,
      path,
    })
  }
  return findings
}

function environmentFindings(agents: ScanContext['agents']): Finding[] {
  if (agents.length === 0) return []
  const findings: Finding[] = []
  for (const [key, value] of Object.entries(process.env)) {
    const match = classifySecret(key, value)
    if (!match) continue
    findings.push({
      category: 'secret',
      severity: 'high',
      title: `${key} is exported in your shell environment`,
      detail: `${match.label} inherited by every AI agent, MCP server, and subprocess you launch from this shell. Move it into a per-project env file or a secrets manager.`,
    })
  }
  return findings
}

function envFileFindings(home: string, project: string): Finding[] {
  const findings: Finding[] = []
  const candidates = [
    join(home, '.env'),
    ...['.env', '.env.local', '.env.development', '.env.production', '.env.staging'].map((f) => join(project, f)),
  ]
  for (const path of candidates) {
    if (!existsSync(path)) continue
    const text = readText(path)
    if (text === undefined) continue
    const vars = parseEnvFile(text)
    const hits = Object.entries(vars)
      .map(([k, v]) => ({ key: k, match: classifySecret(k, v) }))
      .filter((h) => h.match)
    if (hits.length === 0) continue
    const inHome = path.startsWith(home) && !path.startsWith(project)
    const tracked = !inHome && isTrackedInGit(project, path)
    findings.push({
      category: 'secret',
      severity: tracked ? 'critical' : inHome || hits.length >= 3 ? 'high' : 'medium',
      title: tracked ? `${path.replace(project, '.')} with ${hits.length} credential${hits.length > 1 ? 's' : ''} is committed to git` : `${hits.length} credential${hits.length > 1 ? 's' : ''} in ${path.replace(home, '~')}`,
      detail: `${hits.map((h) => h.key).join(', ')}. ${tracked ? 'This file is tracked by the repository, so every clone and every agent that reads the repo has these values. Add it to .gitignore, rotate the keys, and purge the history.' : 'Any agent working in this directory can read this file, and most will, since .env files are rarely in their deny lists.'}`,
      path,
    })
  }
  return findings
}

function credentialStoreFindings(home: string, agents: ScanContext['agents']): Finding[] {
  const findings: Finding[] = []
  const slugs = new Set(agents.map((a) => a.slug))
  const channelEnvs = (() => {
    try {
      return fg.sync('.claude/channels/*/.env', { cwd: home, dot: true, absolute: true, suppressErrors: true })
    } catch {
      return [] as string[]
    }
  })()
  const stores = [...credentialStores(home), ...channelEnvs.map((path) => ({ path, agent: 'claude-code', label: `Claude Code ${path.split('/').at(-2)} channel bot token` }))]
  for (const store of stores) {
    if (!existsSync(store.path)) continue
    if (agents.length > 0 && !slugs.has(store.agent)) continue
    findings.push({
      category: 'secret',
      severity: 'high',
      title: `${store.label} stored in plaintext`,
      detail: `${store.path.replace(home, '~')} holds long lived tokens on disk. Any other agent, MCP server, or npm postinstall script running as you can read and reuse them.`,
      path: store.path,
      agent: store.agent,
    })
  }
  for (const file of stateFiles(home)) {
    if (!existsSync(file.path)) continue
    if (agents.length > 0 && !slugs.has(file.agent)) continue
    const json = readJson(file.path)
    if (json === undefined) continue
    const hits: string[] = []
    walkStrings(json, (path, value) => {
      if (/mcpServers|env\./.test(path)) return
      const match = classifyValue(value)
      if (match) hits.push(`${path} (${match.label})`)
    })
    if (hits.length === 0) continue
    findings.push({
      category: 'secret',
      severity: 'high',
      title: `Plaintext token${hits.length > 1 ? 's' : ''} inside ${file.label}`,
      detail: `${hits.slice(0, 5).join('; ')}${hits.length > 5 ? ` and ${hits.length - 5} more` : ''}. This file is world readable to every process running as you.`,
      path: file.path,
      agent: file.agent,
    })
  }
  return findings
}

function appSupportDir(home: string): string {
  if (process.platform === 'darwin') return join(home, 'Library', 'Application Support')
  if (process.platform === 'win32') return process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming')
  return join(home, '.config')
}

function claudeDesktopFindings(home: string, agents: ScanContext['agents']): Finding[] {
  if (agents.length > 0 && !agents.some((a) => a.slug === 'claude-desktop')) return []
  const path = join(appSupportDir(home), 'Claude', 'config.json')
  const json = readJson(path)
  if (!json || typeof json !== 'object') return []
  const keys = Object.keys(json as Record<string, unknown>).filter((k) => /^oauth:tokenCache/i.test(k) && typeof (json as Record<string, unknown>)[k] === 'string')
  if (keys.length === 0) return []
  return [{
    category: 'secret',
    severity: 'high',
    title: 'Claude Desktop OAuth token cache stored in plaintext',
    detail: `${path.replace(home, '~')} holds ${keys.join(' and ')}. That is the session token for your Claude account, readable by every process running as you, including every MCP server Claude Desktop starts.`,
    path,
    agent: 'claude-desktop',
  }]
}

export async function scanSecrets(ctx: ScanContext, servers: McpServer[]): Promise<Finding[]> {
  return [
    ...claudeDesktopFindings(ctx.home, ctx.agents),
    ...mcpSecretFindings(servers, ctx.project),
    ...environmentFindings(ctx.agents),
    ...envFileFindings(ctx.home, ctx.project),
    ...credentialStoreFindings(ctx.home, ctx.agents),
  ]
}
