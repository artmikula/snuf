import { describe, it, expect, vi, beforeEach } from 'vitest'

vi.mock('node:fs', () => ({
  existsSync: vi.fn(),
}))

vi.mock('node:child_process', () => ({
  execSync: vi.fn(),
}))

vi.mock('node:os', () => ({
  homedir: vi.fn(() => '/home/testuser'),
}))

import { detectAgent } from '../../src/agents/claude-code.js'
import { existsSync } from 'node:fs'
import { execSync } from 'node:child_process'

describe('detectAgent (claude-code)', () => {
  beforeEach(() => {
    vi.clearAllMocks()
  })

  it('returns null when no config paths exist', async () => {
    vi.mocked(existsSync).mockReturnValue(false)
    const result = await detectAgent()
    expect(result).toBeNull()
  })

  it('returns Agent when ~/.claude directory exists', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude'
    )
    vi.mocked(execSync).mockReturnValue(Buffer.from('1.2.3'))

    const result = await detectAgent()
    expect(result).not.toBeNull()
    expect(result?.slug).toBe('claude-code')
    expect(result?.name).toBe('Claude Code')
    expect(result?.configPaths).toContain('/home/testuser/.claude')
  })

  it('returns Agent when ~/.claude.json exists', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude.json'
    )
    vi.mocked(execSync).mockReturnValue(Buffer.from(''))

    const result = await detectAgent()
    expect(result).not.toBeNull()
    expect(result?.configPaths).toContain('/home/testuser/.claude.json')
  })

  it('sets running=true when pgrep exits 0', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude'
    )
    vi.mocked(execSync).mockReturnValue(Buffer.from('12345'))

    const result = await detectAgent()
    expect(result?.running).toBe(true)
  })

  it('sets running=false when pgrep throws', async () => {
    vi.mocked(existsSync).mockImplementation(
      (p) => p === '/home/testuser/.claude'
    )
    vi.mocked(execSync).mockImplementation((cmd: string) => {
      if (String(cmd).includes('pgrep')) throw new Error('no process')
      return Buffer.from('1.0.0')
    })

    const result = await detectAgent()
    expect(result?.running).toBe(false)
  })

  it('collects multiple existing config paths', async () => {
    vi.mocked(existsSync).mockReturnValue(true)
    vi.mocked(execSync).mockReturnValue(Buffer.from(''))

    const result = await detectAgent()
    expect(result?.configPaths.length).toBeGreaterThanOrEqual(2)
  })
})
