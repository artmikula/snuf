import { describe, it, expect, afterEach, beforeEach } from 'vitest'
import { runScan } from '../src/scanner/index.js'
import { renderTerminal } from '../src/reporter/terminal.js'
import { renderMarkdown } from '../src/reporter/markdown.js'
import { renderJson } from '../src/reporter/json.js'
import { sandbox, type Sandbox } from './helpers.js'

let box: Sandbox
let savedHome: string | undefined

beforeEach(() => {
  savedHome = process.env['HOME']
})

afterEach(() => {
  process.env['HOME'] = savedHome
  box?.cleanup()
})

const SECRET = 'sk-proj-' + 'q'.repeat(40)

describe('end to end scan', () => {
  it('runs every scanner against a deliberately bad home directory and never prints secret values', async () => {
    box = sandbox()
    process.env['HOME'] = box.home
    box.write('home/.claude.json', JSON.stringify({ projects: { [box.home]: {} }, mcpServers: { pg: { command: 'npx', args: ['-y', 'mcp-remoto'], env: { OPENAI_API_KEY: SECRET } } } }))
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }))
    box.write('home/.ssh/id_ed25519', 'key')
    box.write('home/work/app/.git/config', '[core]\n\tfsmonitor = ./x.sh\n')
    box.write('home/work/app/.github/workflows/claude.yml', 'on: issues\njobs:\n  c:\n    steps:\n      - uses: anthropics/claude-code-action@v1\n        with:\n          allowed_non_write_users: "*"\n')
    box.write('home/.openclaw/openclaw.json', JSON.stringify({ gateway: { bind: 'lan', auth: { mode: 'none' } } }))

    const result = await runScan({ project: box.project })
    const slugs = result.agents.map((a) => a.slug)
    expect(slugs).toContain('claude-code')
    expect(slugs).toContain('openclaw')
    expect(result.score).toBeGreaterThan(80)

    const categories = new Set(result.findings.map((f) => f.category))
    for (const c of ['secret', 'shell', 'file-access', 'mcp', 'git', 'ci']) expect(categories).toContain(c)
    expect(result.findings.some((f) => f.title.includes('GitSpawn') && f.severity === 'critical')).toBe(true)
    expect(result.findings.some((f) => f.title.includes('typosquat'))).toBe(true)
    expect(result.findings.some((f) => f.title.includes('anyone on GitHub'))).toBe(true)
    expect(result.findings.some((f) => f.title.includes('no authentication'))).toBe(true)
    expect(result.findings.some((f) => f.title.includes('home directory as the project'))).toBe(true)

    const outputs = [
      renderTerminal(result, {}, box.home),
      renderTerminal(result, { quick: true }, box.home),
      renderMarkdown(result, {}, box.home),
      renderJson(result, {}),
    ]
    for (const out of outputs) {
      expect(out).not.toContain('q'.repeat(20))
      expect(out).not.toContain(SECRET)
    }
    expect(outputs[0]).toContain('Git config')
    expect(outputs[0]).toContain('CI workflows')
    expect(outputs[2]).toContain('Centipede Software')
  })

  it('reports a clean machine as clean', async () => {
    box = sandbox()
    process.env['HOME'] = box.home
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { deny: ['Read(./.env)'] } }))
    const result = await runScan({ project: box.project })
    expect(result.agents.map((a) => a.slug)).toEqual(['claude-code'])
    const fromDisk = result.findings.filter((f) => !f.title.includes('shell environment'))
    expect(fromDisk.filter((f) => f.severity === 'critical' || f.severity === 'high')).toEqual([])
    expect(fromDisk.every((f) => f.severity === 'info' || f.severity === 'low')).toBe(true)
  })
})
