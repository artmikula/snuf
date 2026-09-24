import { describe, it, expect } from 'vitest'
import { stripJsonComments, parseTomlSubset, parseEnvFile, walkStrings } from '../../src/scanner/config-parsers.js'

describe('config parsers', () => {
  it('strips comments and trailing commas but keeps urls inside strings', () => {
    const text = `{
  // line comment
  "url": "https://example.com/path", /* block */
  "list": [1, 2,],
}`
    const parsed = JSON.parse(stripJsonComments(text))
    expect(parsed.url).toBe('https://example.com/path')
    expect(parsed.list).toEqual([1, 2])
  })

  it('parses the toml subset used by codex and vibe', () => {
    const toml = parseTomlSubset(`
approval_policy = "never" # trailing comment
sandbox_mode = "danger-full-access"
[mcp_servers.one]
command = "npx"
args = ["-y", "pkg@1.0.0"]
env = { A = "1", B = "two" }
[mcp_servers.one.env]
C = "3"
[mcp_servers."quoted name"]
url = "https://x"
`)
    expect(toml['approval_policy']).toBe('never')
    const one = (toml['mcp_servers'] as Record<string, Record<string, unknown>>)['one']!
    expect(one['args']).toEqual(['-y', 'pkg@1.0.0'])
    expect(one['env']).toEqual({ A: '1', B: 'two', C: '3' })
    expect((toml['mcp_servers'] as Record<string, Record<string, unknown>>)['quoted name']!['url']).toBe('https://x')
  })

  it('parses env files with export, quotes and comments', () => {
    const vars = parseEnvFile(`
# comment
export FOO="bar baz"
BAR='single'
BAZ=plain # trailing
EMPTY=
`)
    expect(vars).toEqual({ FOO: 'bar baz', BAR: 'single', BAZ: 'plain', EMPTY: '' })
  })

  it('walks nested strings with paths', () => {
    const seen: string[] = []
    walkStrings({ a: { b: ['x', { c: 'y' }] }, d: 1 }, (p, v) => seen.push(`${p}=${v}`))
    expect(seen).toEqual(['a.b[0]=x', 'a.b[1].c=y'])
  })
})
