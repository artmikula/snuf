import { describe, it, expect, afterEach } from 'vitest'
import { scanMcpServers } from '../../src/scanner/mcp.js'
import { sandbox, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('scanMcpServers', () => {
  it('returns nothing when no config files exist', async () => {
    box = sandbox()
    const { servers, findings } = await scanMcpServers(box.ctx())
    expect(servers).toEqual([])
    expect(findings).toEqual([])
  })

  it('reads Claude Desktop config from Application Support on macOS', async () => {
    box = sandbox()
    const rel = process.platform === 'darwin' ? 'home/Library/Application Support/Claude/claude_desktop_config.json' : 'home/.config/Claude/claude_desktop_config.json'
    box.write(rel, JSON.stringify({ mcpServers: { fs: { command: 'npx', args: ['-y', '@modelcontextprotocol/server-filesystem', '/tmp'] } } }))
    const { servers, findings } = await scanMcpServers(box.ctx())
    expect(servers).toHaveLength(1)
    expect(servers[0]!.agent).toBe('claude-desktop')
    expect(servers[0]!.isKnown).toBe(true)
    expect(findings).toEqual([])
  })

  it('reads project scoped servers nested under projects in ~/.claude.json', async () => {
    box = sandbox()
    box.write('home/.claude.json', JSON.stringify({
      mcpServers: { top: { command: 'npx', args: ['-y', 'some-random-mcp'] } },
      projects: { '/repo': { mcpServers: { nested: { command: 'uvx', args: ['other-thing'] } } } },
    }))
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers.map((s) => s.name)).toEqual(['top', 'nested (/repo)'])
    expect(servers[0]!.isKnown).toBe(false)
  })

  it('reads project .mcp.json for Claude Code', async () => {
    box = sandbox()
    box.write('home/work/app/.mcp.json', JSON.stringify({ mcpServers: { remote: { url: 'https://example.com/mcp' } } }))
    const { servers, findings } = await scanMcpServers(box.ctx())
    expect(servers[0]!.transport).toBe('http')
    expect(servers[0]!.hasNetworkAccess).toBe(true)
    expect(findings).toEqual([])
  })

  it('parses Codex config.toml mcp_servers tables', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', `
model = "gpt-5"
approval_policy = "on-request"

[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]

[mcp_servers.github.env]
GITHUB_TOKEN = "ghp_${'a'.repeat(36)}"

[mcp_servers.custom]
command = "python3"
args = ["server.py"]
`)
    const { servers, findings } = await scanMcpServers(box.ctx())
    expect(servers.map((s) => s.name).sort()).toEqual(['custom', 'github'])
    const github = servers.find((s) => s.name === 'github')!
    expect(github.isKnown).toBe(true)
    expect(github.secretKeys).toEqual(['GITHUB_TOKEN'])
    expect(github.envVars!['GITHUB_TOKEN']).not.toContain('aaaaaaaaaa')
    expect(findings.some((f) => f.title.includes('custom') && f.severity === 'medium')).toBe(true)
  })

  it('never exposes raw env values', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { x: { command: 'node', args: ['x.js'], env: { OPENAI_API_KEY: 'sk-proj-' + 'z'.repeat(40) } } } }))
    const { servers } = await scanMcpServers(box.ctx())
    expect(JSON.stringify(servers)).not.toContain('zzzzzzzzzz')
    expect(servers[0]!.secretKeys).toEqual(['OPENAI_API_KEY'])
  })

  it('flags unrecognized local servers holding credentials as high', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { sketchy: { command: 'npx', args: ['-y', 'sketchy-mcp'], env: { API_KEY: 'real-looking-value-123456' } } } }))
    const { findings } = await scanMcpServers(box.ctx())
    expect(findings[0]!.severity).toBe('high')
    expect(findings[0]!.category).toBe('mcp')
  })

  it('treats env references like ${VAR} as not secrets', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { ok: { command: 'npx', args: ['-y', 'some-mcp'], env: { API_KEY: '${API_KEY}' } } } }))
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers[0]!.secretKeys).toEqual([])
  })

  it('captures Authorization headers on remote servers', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { r: { url: 'https://api.example.com/mcp', headers: { Authorization: 'Bearer abcdefghijklmnop' } } } }))
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers[0]!.secretKeys).toEqual(['header:Authorization'])
    expect(servers[0]!.headers!['Authorization']).not.toContain('abcdefghijklmnop')
  })

  it('reads VS Code style servers key and JSONC comments', async () => {
    box = sandbox()
    box.write('home/work/app/.vscode/mcp.json', `{
  // comment
  "servers": {
    "playwright": { "command": "npx", "args": ["@playwright/mcp@latest"], },
  }
}`)
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers).toHaveLength(1)
    expect(servers[0]!.isKnown).toBe(true)
  })

  it('reads OpenCode array command format', async () => {
    box = sandbox()
    box.write('home/.config/opencode/opencode.json', JSON.stringify({ mcp: { local: { type: 'local', command: ['bun', 'x', 'my-mcp'], environment: { MY_KEY: 'sk-ant-' + 'q'.repeat(30) } } } }))
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers[0]!.command).toBe('bun')
    expect(servers[0]!.secretKeys).toEqual(['MY_KEY'])
  })

  it('skips malformed files', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', '{ not json')
    const { servers } = await scanMcpServers(box.ctx())
    expect(servers).toEqual([])
  })

  it('honors --agent by skipping other agents sources', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { a: { command: 'npx', args: ['x'] } } }))
    box.write('home/.claude.json', JSON.stringify({ mcpServers: { b: { command: 'npx', args: ['y'] } } }))
    const { servers } = await scanMcpServers(box.ctx([], { agent: 'cursor' }))
    expect(servers.map((s) => s.name)).toEqual(['a'])
  })

  it('flags plain http remote servers', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', JSON.stringify({ mcpServers: { r: { url: 'http://mcp.example.com/sse' } } }))
    const { findings } = await scanMcpServers(box.ctx())
    expect(findings[0]!.title).toContain('plain HTTP')
  })
})
