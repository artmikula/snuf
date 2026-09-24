import { describe, it, expect, afterEach } from 'vitest'
import { scanSecrets } from '../../src/scanner/secrets.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'
import type { McpServer } from '../../src/types.js'

let box: Sandbox
afterEach(() => box?.cleanup())

const server = (over: Partial<McpServer>): McpServer => ({
  name: 's', agent: 'cursor', transport: 'stdio', secretKeys: [], hasNetworkAccess: false, hasShellAccess: true, isKnown: false, source: '~/.cursor/mcp.json', ...over,
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
