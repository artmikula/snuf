import { describe, it, expect } from 'vitest'
import { renderJson } from '../../src/reporter/json.js'
import { renderMarkdown } from '../../src/reporter/markdown.js'
import { renderTerminal } from '../../src/reporter/terminal.js'
import type { ScanResult } from '../../src/types.js'

const result: ScanResult = {
  version: '0.0.0',
  agents: [{ name: 'Claude Code', slug: 'claude-code', running: true, configPaths: ['/home/u/.claude'] }],
  mcpServers: [{ name: 'x', agent: 'cursor', transport: 'stdio', command: 'npx', args: ['x'], envVars: { KEY: 'abcd…yz (40 chars)' }, secretKeys: ['KEY'], hasNetworkAccess: false, hasShellAccess: true, isKnown: false, source: '~/.cursor/mcp.json' }],
  findings: [
    { category: 'secret', severity: 'critical', title: 'KEY stored in plaintext in MCP config (x)', detail: 'd' },
    { category: 'shell', severity: 'info', title: 'Claude Code prompts before running commands', detail: 'd' },
  ],
  score: 38,
  scannedAt: '2026-01-01T00:00:00.000Z',
  platform: 'darwin',
  projectDir: '/home/u/app',
}

describe('reporters', () => {
  it('json respects --severity and --quick', () => {
    const full = JSON.parse(renderJson(result, {}))
    expect(full.findings).toHaveLength(2)
    expect(full.band).toBe('Caution')
    const high = JSON.parse(renderJson(result, { severity: 'high' }))
    expect(high.findings).toHaveLength(1)
    const quick = JSON.parse(renderJson(result, { quick: true }))
    expect(Object.keys(quick).sort()).toEqual(['band', 'counts', 'score'])
  })

  it('markdown numbers recommendations from 1 and groups by category', () => {
    const md = renderMarkdown(result, {}, '/home/u')
    expect(md).toContain('1. Move credentials out of MCP config files')
    expect(md).toContain('### Secrets (1)')
    expect(md).toContain('~/.claude')
  })

  it('terminal quick mode prints only the score', () => {
    expect(renderTerminal(result, { quick: true }, '/home/u')).toBe('38/100 Caution')
    expect(renderTerminal(result, {}, '/home/u')).toContain('Do this first')
  })
})
