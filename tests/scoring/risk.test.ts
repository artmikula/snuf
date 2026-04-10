import { describe, it, expect } from 'vitest'
import { calculateScore, scoreBand } from '../../src/scoring/risk.js'
import type { Finding, Agent, McpServer } from '../../src/types.js'

const noAgents: Agent[] = []
const noMcp: McpServer[] = []

describe('calculateScore', () => {
  it('returns 0 for no findings', () => {
    expect(calculateScore([], noAgents, noMcp)).toBe(0)
  })

  it('scores info findings as 0', () => {
    const findings: Finding[] = [
      { category: 'agent', severity: 'info', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(0)
  })

  it('scores low as 5', () => {
    const findings: Finding[] = [
      { category: 'mcp', severity: 'low', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(5)
  })

  it('scores medium as 15', () => {
    const findings: Finding[] = [
      { category: 'mcp', severity: 'medium', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(15)
  })

  it('scores high as 30', () => {
    const findings: Finding[] = [
      { category: 'mcp', severity: 'high', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(30)
  })

  it('scores critical as 50', () => {
    const findings: Finding[] = [
      { category: 'mcp', severity: 'critical', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(50)
  })

  it('is additive across multiple findings', () => {
    const findings: Finding[] = [
      { category: 'mcp', severity: 'medium', title: 'x', detail: 'x' },
      { category: 'mcp', severity: 'high', title: 'x', detail: 'x' },
    ]
    expect(calculateScore(findings, noAgents, noMcp)).toBe(45)
  })

  it('caps at 100', () => {
    const findings: Finding[] = Array(5).fill(
      { category: 'mcp', severity: 'critical', title: 'x', detail: 'x' }
    )
    expect(calculateScore(findings, noAgents, noMcp)).toBe(100)
  })
})

describe('scoreBand', () => {
  it('0 is Clean', () => expect(scoreBand(0)).toBe('Clean'))
  it('20 is Clean', () => expect(scoreBand(20)).toBe('Clean'))
  it('21 is Caution', () => expect(scoreBand(21)).toBe('Caution'))
  it('40 is Caution', () => expect(scoreBand(40)).toBe('Caution'))
  it('41 is Warning', () => expect(scoreBand(41)).toBe('Warning'))
  it('60 is Warning', () => expect(scoreBand(60)).toBe('Warning'))
  it('61 is Danger', () => expect(scoreBand(61)).toBe('Danger'))
  it('80 is Danger', () => expect(scoreBand(80)).toBe('Danger'))
  it('81 is Critical', () => expect(scoreBand(81)).toBe('Critical'))
  it('100 is Critical', () => expect(scoreBand(100)).toBe('Critical'))
})
