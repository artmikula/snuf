import { describe, it, expect } from 'vitest'
import { calculateScore, scoreBand, sortFindings } from '../../src/scoring/risk.js'
import type { Finding, Severity } from '../../src/types.js'

const f = (severity: Severity): Finding => ({ category: 'mcp', severity, title: 't', detail: 'd' })

describe('calculateScore', () => {
  it('is 0 with no findings', () => {
    expect(calculateScore([])).toBe(0)
  })

  it('ignores info findings', () => {
    expect(calculateScore([f('info'), f('info')])).toBe(0)
  })

  it('does not saturate on a single critical', () => {
    const one = calculateScore([f('critical')])
    expect(one).toBeGreaterThan(30)
    expect(one).toBeLessThan(50)
  })

  it('grows with more findings but stays under 100', () => {
    const a = calculateScore([f('high')])
    const b = calculateScore([f('high'), f('high')])
    const c = calculateScore(Array.from({ length: 20 }, () => f('critical')))
    expect(b).toBeGreaterThan(a)
    expect(c).toBeLessThanOrEqual(100)
  })

  it('ranks a typical clean laptop as clean or caution', () => {
    expect(calculateScore([f('low'), f('low'), f('medium'), f('info')])).toBeLessThanOrEqual(20)
  })

  it('ranks bypass mode plus exposed keys as danger or critical', () => {
    expect(calculateScore([f('critical'), f('critical'), f('high'), f('high'), f('medium')])).toBeGreaterThan(60)
  })
})

describe('scoreBand', () => {
  it('maps boundaries', () => {
    expect(scoreBand(0)).toBe('Clean')
    expect(scoreBand(20)).toBe('Clean')
    expect(scoreBand(21)).toBe('Caution')
    expect(scoreBand(40)).toBe('Caution')
    expect(scoreBand(41)).toBe('Warning')
    expect(scoreBand(60)).toBe('Warning')
    expect(scoreBand(61)).toBe('Danger')
    expect(scoreBand(80)).toBe('Danger')
    expect(scoreBand(81)).toBe('Critical')
    expect(scoreBand(100)).toBe('Critical')
  })
})

describe('sortFindings', () => {
  it('orders most severe first', () => {
    const sorted = sortFindings([f('low'), f('critical'), f('medium'), f('high'), f('info')])
    expect(sorted.map((x) => x.severity)).toEqual(['critical', 'high', 'medium', 'low', 'info'])
  })
})
