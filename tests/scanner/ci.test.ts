import { describe, it, expect, afterEach } from 'vitest'
import { scanCi } from '../../src/scanner/ci.js'
import { sandbox, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('scanCi', () => {
  it('ignores workflows without agent actions', async () => {
    box = sandbox()
    box.write('home/work/app/.github/workflows/ci.yml', 'on: [push]\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n')
    expect(await scanCi(box.ctx())).toEqual([])
  })

  it('flags allowed_non_write_users wildcard as high', async () => {
    box = sandbox()
    box.write('home/work/app/.github/workflows/claude.yml', `on:
  issue_comment:
    types: [created]
permissions:
  contents: write
  id-token: write
jobs:
  claude:
    steps:
      - uses: anthropics/claude-code-action@v1
        with:
          allowed_non_write_users: "*"
          anthropic_api_key: \${{ secrets.ANTHROPIC_API_KEY }}
`)
    const findings = await scanCi(box.ctx())
    const open = findings.find((f) => f.title.includes('anyone on GitHub'))
    expect(open?.severity).toBe('high')
    expect(open?.detail).toContain('ANTHROPIC_API_KEY')
    expect(findings.find((f) => f.title.includes('not pinned'))?.severity).toBe('low')
  })

  it('rates untrusted triggers medium when write permissions or secrets are present', async () => {
    box = sandbox()
    box.write('home/work/app/.github/workflows/gemini.yml', `on:
  pull_request_target:
permissions:
  contents: write
jobs:
  review:
    steps:
      - uses: google-github-actions/run-gemini-cli@0123456789abcdef0123456789abcdef01234567
`)
    const findings = await scanCi(box.ctx())
    expect(findings).toHaveLength(1)
    expect(findings[0]!.severity).toBe('medium')
    expect(findings[0]!.agent).toBe('gemini-cli')
  })

  it('stays low for push triggered agent workflows pinned to a sha', async () => {
    box = sandbox()
    box.write('home/work/app/.github/workflows/codex.yml', 'on: push\njobs:\n  x:\n    steps:\n      - uses: openai/codex-action@0123456789abcdef0123456789abcdef01234567\n')
    expect(await scanCi(box.ctx())).toEqual([])
  })

  it('respects --agent', async () => {
    box = sandbox()
    box.write('home/work/app/.github/workflows/claude.yml', 'on: issues\njobs:\n  x:\n    steps:\n      - uses: anthropics/claude-code-action@beta\n')
    expect(await scanCi(box.ctx([], { agent: 'codex' }))).toEqual([])
    expect((await scanCi(box.ctx([], { agent: 'claude-code' }))).length).toBeGreaterThan(0)
  })
})
