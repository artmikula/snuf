import { describe, it, expect, afterEach } from 'vitest'
import { scanSecrets } from '../../src/scanner/secrets.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'
import type { McpServer } from '../../src/types.js'

let box: Sandbox
afterEach(() => box?.cleanup())

const server = (over: Partial<McpServer>): McpServer => ({
  name: 's', agent: 'cursor', transport: 'stdio', secretKeys: [], hasNetworkAccess: false, hasShellAccess: true, isKnown: false, source: '~/.cursor/mcp.json', sourcePath: '/nonexistent/.cursor/mcp.json', ...over,
})

describe('scanSecrets', () => {
  it('turns MCP secret keys into critical findings', async () => {
    box = sandbox()
    const findings = await scanSecrets(box.ctx([]), [server({ secretKeys: ['OPENAI_API_KEY', 'header:Authorization'] })])
    expect(findings).toHaveLength(2)
    expect(findings.every((f) => f.severity === 'critical')).toBe(true)
    expect(findings[1]!.detail).toContain('header')
  })

  it('finds credentials in project env files and never prints values', async () => {
    box = sandbox()
    box.write('home/work/app/.env', 'OPENAI_API_KEY=sk-proj-' + 'k'.repeat(40) + '\nPORT=3000\nDATABASE_URL=postgres://u:p@host/db\nSTRIPE_SECRET_KEY=sk_live_' + 'm'.repeat(24) + '\n')
    const findings = await scanSecrets(box.ctx([agent('claude-code')]), [])
    const env = findings.find((f) => f.title.includes('.env'))!
    expect(env.title).toContain('3 credentials')
    expect(env.severity).toBe('high')
    expect(JSON.stringify(findings)).not.toContain('kkkkkkkkkk')
  })

  it('flags plaintext agent credential stores only for detected agents', async () => {
    box = sandbox()
    box.write('home/.codex/auth.json', '{}')
    const none = await scanSecrets(box.ctx([agent('cursor')]), [])
    expect(none.some((f) => f.title.includes('Codex'))).toBe(false)
    const some = await scanSecrets(box.ctx([agent('codex')]), [])
    expect(some.some((f) => f.title.includes('Codex CLI auth tokens'))).toBe(true)
  })

  it('finds tokens embedded in agent state files', async () => {
    box = sandbox()
    box.write('home/.claude.json', JSON.stringify({ oauth: { accessToken: 'sk-ant-oat01-' + 'r'.repeat(40) }, mcpServers: { x: { env: { K: 'sk-ant-' + 'q'.repeat(30) } } } }))
    const findings = await scanSecrets(box.ctx([agent('claude-code')]), [])
    const hit = findings.find((f) => f.title.includes('~/.claude.json'))!
    expect(hit.detail).toContain('oauth.accessToken')
    expect(hit.detail).not.toContain('mcpServers')
    expect(JSON.stringify(findings)).not.toContain('rrrrrrrrrr')
  })
})

describe('scanSecrets git tracked files', () => {
  it('flags .env and MCP configs that are committed to the repository', async () => {
    const { execFileSync } = await import('node:child_process')
    const { scanMcpServers } = await import('../../src/scanner/mcp.js')
    box = sandbox()
    box.write('home/work/app/.env', 'OPENAI_API_KEY=sk-proj-' + 'q'.repeat(40) + '\n')
    box.write('home/work/app/.cursor/mcp.json', JSON.stringify({ mcpServers: { x: { command: 'node', args: ['x.js'], env: { OPENAI_API_KEY: 'sk-proj-' + 'z'.repeat(40) } } } }))
    const git = (...args: string[]) => execFileSync('git', args, { cwd: box.project, stdio: 'ignore' })
    git('init', '-q')
    git('add', '.env', '.cursor/mcp.json')
    const { servers } = await scanMcpServers(box.ctx())
    const findings = await scanSecrets(box.ctx([agent('cursor')]), servers)
    const env = findings.find((f) => f.title.includes('.env') && f.title.includes('committed'))
    expect(env?.severity).toBe('critical')
    const mcp = findings.find((f) => f.title.includes('MCP config with') && f.title.includes('committed'))
    expect(mcp?.severity).toBe('critical')
    expect(mcp?.detail).toContain('OPENAI_API_KEY')
  })

  it('does not flag untracked files as committed', async () => {
    const { execFileSync } = await import('node:child_process')
    box = sandbox()
    box.write('home/work/app/.env', 'OPENAI_API_KEY=sk-proj-' + 'q'.repeat(40) + '\n')
    execFileSync('git', ['init', '-q'], { cwd: box.project, stdio: 'ignore' })
    const findings = await scanSecrets(box.ctx([agent('cursor')]), [])
    expect(findings.some((f) => f.title.includes('committed'))).toBe(false)
    expect(findings.some((f) => f.title.includes('1 credential in'))).toBe(true)
  })
})

describe('claude desktop token cache', () => {
  it('flags oauth token cache keys in config.json', async () => {
    box = sandbox()
    const rel = process.platform === 'darwin' ? 'home/Library/Application Support/Claude/config.json' : 'home/.config/Claude/config.json'
    box.write(rel, JSON.stringify({ locale: 'en', 'oauth:tokenCache': 'djEw' + 'x'.repeat(60), 'oauth:tokenCacheV2': 'djEw' + 'y'.repeat(60) }))
    const findings = await scanSecrets(box.ctx([agent('claude-desktop')]), [])
    const hit = findings.find((f) => f.title.includes('Claude Desktop OAuth'))
    expect(hit?.severity).toBe('high')
    expect(JSON.stringify(findings)).not.toContain('xxxxxxxxxx')
  })
})

describe('claude channels', () => {
  it('reports channel .env files as plaintext credential stores', async () => {
    box = sandbox()
    box.write('home/.claude/channels/discord/.env', 'DISCORD_BOT_TOKEN=abc\n')
    const findings = await scanSecrets(box.ctx([agent('claude-code')]), [])
    expect(findings.find((f) => f.title.includes('discord channel bot token'))?.severity).toBe('high')
  })
})
