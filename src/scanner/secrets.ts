import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Finding, McpServer, ScanContext } from '../types.js'
import { readJson, readText, parseEnvFile, walkStrings } from './config-parsers.js'
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
  ]
}

function stateFiles(home: string): CredentialStore[] {
  return [
    { path: join(home, '.claude.json'), agent: 'claude-code', label: '~/.claude.json' },
    { path: join(home, '.openclaw', 'openclaw.json'), agent: 'openclaw', label: '~/.openclaw/openclaw.json' },
    { path: join(home, '.config', 'amp', 'settings.json'), agent: 'amp', label: 'Amp settings' },
    { path: join(home, '.continue', 'config.json'), agent: 'continue', label: 'Continue config' },
    { path: join(home, '.config', 'zed', 'settings.json'), agent: 'zed', label: 'Zed settings' },
  ]
}

function mcpSecretFindings(servers: McpServer[]): Finding[] {
  const findings: Finding[] = []
  for (const server of servers) {
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
    findings.push({
      category: 'secret',
      severity: inHome || hits.length >= 3 ? 'high' : 'medium',
      title: `${hits.length} credential${hits.length > 1 ? 's' : ''} in ${path.replace(home, '~')}`,
      detail: `${hits.map((h) => h.key).join(', ')}. Any agent working in this directory can read this file, and most will, since .env files are rarely in their deny lists.`,
      path,
    })
  }
  return findings
}

function credentialStoreFindings(home: string, agents: ScanContext['agents']): Finding[] {
  const findings: Finding[] = []
  const slugs = new Set(agents.map((a) => a.slug))
  for (const store of credentialStores(home)) {
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

export async function scanSecrets(ctx: ScanContext, servers: McpServer[]): Promise<Finding[]> {
  return [
    ...mcpSecretFindings(servers),
    ...environmentFindings(ctx.agents),
    ...envFileFindings(ctx.home, ctx.project),
    ...credentialStoreFindings(ctx.home, ctx.agents),
  ]
}
