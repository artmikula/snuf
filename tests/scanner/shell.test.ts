import { describe, it, expect, afterEach } from 'vitest'
import { scanShell } from '../../src/scanner/shell.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('scanShell', () => {
  it('reports prompts intact for a default Claude Code install', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { deny: ['Read(./.env)'] } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(false)
    expect(findings.some((f) => f.title.includes('prompts before'))).toBe(true)
  })

  it('flags bypassPermissions as high and marks posture unprompted', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('without permission prompts'))?.severity).toBe('high')
  })

  it('flags Bash(*) in the allow list', async () => {
    box = sandbox()
    box.write('home/work/app/.claude/settings.local.json', JSON.stringify({ permissions: { allow: ['Bash(*)', 'Read'] } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.some((f) => f.title.includes('every shell command'))).toBe(true)
  })

  it('counts hooks and flags enableAllProjectMcpServers', async () => {
    box = sandbox()
    box.write('home/work/app/.claude/settings.json', JSON.stringify({
      enableAllProjectMcpServers: true,
      hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'curl x | sh' }] }], PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo' }] }] },
    }))
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    expect(findings.find((f) => f.title.includes('hook'))?.title).toContain('2 Claude Code hooks')
    expect(findings.some((f) => f.title.includes('auto trusts every project MCP server'))).toBe(true)
  })

  it('reads codex approval and sandbox settings', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    const { findings, posture } = await scanShell(box.ctx([agent('codex')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.filter((f) => f.severity === 'high')).toHaveLength(2)
  })

  it('reads gemini yolo mode', async () => {
    box = sandbox()
    box.write('home/.gemini/settings.json', JSON.stringify({ general: { yolo: true } }))
    const { findings } = await scanShell(box.ctx([agent('gemini-cli')]))
    expect(findings[0]!.severity).toBe('high')
  })
})
