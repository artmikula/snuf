import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
  readFileSync: vi.fn(),
}))

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/home/testuser'),
}))

import { scanMcpServers } from '../../src/scanner/mcp.js'
import { existsSync } from 'node:fs'
import { readFileSync } from 'node:fs'

const KNOWN_CONFIG = JSON.stringify({
  mcpServers: {
    filesystem: {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-filesystem', '/home/user'],
      env: {}
    },
    github: {
      command: 'npx',
      args: ['-y', '@modelcontextprotocol/server-github'],
      env: { GITHUB_TOKEN: 'ghp_test' }
    }
  }
})

const UNKNOWN_CONFIG = JSON.stringify({
  mcpServers: {
    'my-custom-server': {
      command: '/usr/local/bin/my-custom-binary',
      args: ['--serve'],
      env: {}
    }
  }
})

const CRITICAL_CONFIG = JSON.stringify({
  mcpServers: {
    'sketchy-mcp': {
      command: 'npx',
      args: ['-y', 'sketchy-package'],
      url: 'https://remote.example.com',
      env: { SECRET_KEY: 'abc123' }
    }
  }
})

describe('scanMcpServers', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    vi.mocked(existsSync).mockReturnValue(false)
  })

  it('returns empty arrays when no config files exist', async () => {
    const { servers, findings } = await scanMcpServers([], {})
    expect(servers).toHaveLength(0)
    expect(findings).toHaveLength(0)
  })

  it('parses known MCP servers correctly', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude/claude_desktop_config.json'
    )
    vi.mocked(readFileSync).mockReturnValue(KNOWN_CONFIG)

    const { servers, findings } = await scanMcpServers([], {})
    expect(servers).toHaveLength(2)
    expect(servers[0].name).toBe('filesystem')
    expect(servers[0].isKnown).toBe(true)
    expect(servers[0].hasShellAccess).toBe(true)
    expect(servers[0].transport).toBe('stdio')
    expect(findings).toHaveLength(0)
  })

  it('flags unknown server as medium finding', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.cursor/mcp.json'
    )
    vi.mocked(readFileSync).mockReturnValue(UNKNOWN_CONFIG)

    const { servers, findings } = await scanMcpServers([], {})
    expect(servers).toHaveLength(1)
    expect(servers[0].isKnown).toBe(false)
    expect(findings).toHaveLength(1)
    expect(findings[0].severity).toBe('medium')
    expect(findings[0].category).toBe('mcp')
  })

  it('flags unknown server with network+shell+env as critical finding', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude/claude_desktop_config.json'
    )
    vi.mocked(readFileSync).mockReturnValue(CRITICAL_CONFIG)

    const { servers, findings } = await scanMcpServers([], {})
    expect(servers[0].hasNetworkAccess).toBe(true)
    expect(servers[0].hasShellAccess).toBe(true)
    expect(findings[0].severity).toBe('critical')
  })

  it('silently skips files with invalid JSON', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude/claude_desktop_config.json'
    )
    vi.mocked(readFileSync).mockReturnValue('{ invalid json }}}')

    const { servers, findings } = await scanMcpServers([], {})
    expect(servers).toHaveLength(0)
    expect(findings).toHaveLength(0)
  })

  it('attaches source label to each server', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.cursor/mcp.json'
    )
    vi.mocked(readFileSync).mockReturnValue(UNKNOWN_CONFIG)

    const { servers } = await scanMcpServers([], {})
    expect(servers[0].source).toBe('cursor')
  })
})
