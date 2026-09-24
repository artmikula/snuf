import { describe, it, expect, afterEach } from 'vitest'
import { scanPermissions } from '../../src/scanner/permissions.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('scanPermissions', () => {
  it('returns nothing when no agents are installed', async () => {
    box = sandbox()
    box.write('home/.ssh/id_ed25519', 'key')
    expect(await scanPermissions(box.ctx([]), { unprompted: false, reasons: [] }, 0)).toEqual([])
  })

  it('rates credential directories by exposure tier', async () => {
    box = sandbox()
    box.write('home/.ssh/id_ed25519', 'key')
    box.write('home/.aws/credentials', 'x')
    const prompted = await scanPermissions(box.ctx([agent('cursor')]), { unprompted: false, reasons: [] }, 0)
    expect(prompted.find((f) => f.title.includes('SSH'))?.severity).toBe('medium')
    const viaMcp = await scanPermissions(box.ctx([agent('cursor')]), { unprompted: false, reasons: [] }, 2)
    expect(viaMcp.find((f) => f.title.includes('SSH'))?.severity).toBe('high')
    const bypass = await scanPermissions(box.ctx([agent('cursor')]), { unprompted: true, reasons: ['bypass'] }, 0)
    expect(bypass.find((f) => f.title.includes('SSH'))?.severity).toBe('critical')
    expect(bypass.find((f) => f.title.includes('AWS'))?.severity).toBe('critical')
  })

  it('detects Claude Code sessions started from the home directory', async () => {
    box = sandbox()
    box.write('home/.claude.json', JSON.stringify({ projects: { [box.home]: {}, [box.project]: {} } }))
    const findings = await scanPermissions(box.ctx([agent('claude-code')]), { unprompted: false, reasons: [] }, 0)
    expect(findings.some((f) => f.title.includes('home directory as the project'))).toBe(true)
  })

  it('does not flag home directory when only real projects are listed', async () => {
    box = sandbox()
    box.write('home/.claude.json', JSON.stringify({ projects: { [box.project]: {} } }))
    const findings = await scanPermissions(box.ctx([agent('claude-code')]), { unprompted: false, reasons: [] }, 0)
    expect(findings.some((f) => f.title.includes('home directory as the project'))).toBe(false)
  })
})
