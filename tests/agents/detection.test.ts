import { describe, it, expect, afterEach, vi } from 'vitest'

vi.mock('node:child_process', () => ({
  execSync: vi.fn((cmd: string) => {
    if (cmd.startsWith('claude')) return Buffer.from('2.1.0 (Claude Code)\n')
    if (cmd.startsWith('cursor')) return Buffer.from('1.7.28\nabcdef0123\narm64\n')
    if (cmd.startsWith('ps ')) return Buffer.from('claude claude --resume\ncodex /Applications/ChatGPT.app/Contents/Resources/codex app-server\nCursor /Applications/Cursor.app/Contents/MacOS/Cursor\n')
    throw new Error('not found')
  }),
}))

import { claudeCode, cursor, codex, copilot } from '../../src/agents/index.js'
import { parseVersion, isProcessRunning } from '../../src/agents/base.js'
import { sandbox, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('agent detection', () => {
  it('returns null when nothing exists', async () => {
    box = sandbox()
    expect(await claudeCode(box.home, box.project)).toBeNull()
  })

  it('detects Claude Code from ~/.claude.json and parses the version', async () => {
    box = sandbox()
    box.write('home/.claude.json', '{}')
    const a = await claudeCode(box.home, box.project)
    expect(a?.slug).toBe('claude-code')
    expect(a?.version).toBe('2.1.0')
    expect(a?.running).toBe(true)
  })

  it('parses multi line VS Code fork version output correctly', async () => {
    box = sandbox()
    box.write('home/.cursor/mcp.json', '{}')
    const a = await cursor(box.home, box.project)
    expect(a?.version).toBe('1.7.28')
  })

  it('detects Copilot CLI from ~/.copilot', async () => {
    box = sandbox()
    box.write('home/.copilot/config.json', '{}')
    expect((await copilot(box.home, box.project))?.slug).toBe('copilot')
  })

  it('does not count a desktop app helper as the CLI running', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', '')
    const a = await codex(box.home, box.project)
    expect(a?.running).toBe(false)
    expect(isProcessRunning(['Cursor'], true)).toBe(true)
  })

  it('parseVersion picks the first version like token', () => {
    expect(parseVersion('codex-cli 0.154.0')).toBe('0.154.0')
    expect(parseVersion('aider 0.86.1')).toBe('0.86.1')
    expect(parseVersion(undefined)).toBeUndefined()
  })
})
