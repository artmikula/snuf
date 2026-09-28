import { describe, it, expect } from 'vitest'
import { advisoryFindings } from '../../src/scanner/advisories.js'
import { agent } from '../helpers.js'

describe('advisoryFindings', () => {
  it('flags versions below known fixes and notes unpatched agents', () => {
    const findings = advisoryFindings([
      { ...agent('codex', 'Codex CLI'), version: '0.120.0' },
      { ...agent('claude-code', 'Claude Code'), version: '2.1.250' },
      { ...agent('claude-code', 'Claude Code'), version: '2.1.80' },
      { ...agent('goose', 'Goose'), version: '1.44.0' },
      { ...agent('cursor', 'Cursor'), version: '2.3.1' },
      agent('hermes', 'Hermes Agent'),
      agent('grok', 'Grok Build'),
    ])
    expect(findings.filter((f) => f.title.startsWith('Codex CLI v0.120.0'))).toHaveLength(1)
    expect(findings.some((f) => f.title.startsWith('Claude Code v2.1.250'))).toBe(false)
    expect(findings.filter((f) => f.title.startsWith('Claude Code v2.1.80'))).toHaveLength(3)
    expect(findings.some((f) => f.title.startsWith('Goose'))).toBe(false)
    expect(findings.find((f) => f.title.startsWith('Cursor'))?.severity).toBe('high')
    expect(findings.filter((f) => f.severity === 'medium').map((f) => f.agent).sort()).toEqual(['grok', 'hermes'])
  })

  it('says nothing without a version for versioned advisories', () => {
    expect(advisoryFindings([agent('codex', 'Codex CLI')])).toEqual([])
  })
})
