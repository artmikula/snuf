import { existsSync, readdirSync, statSync } from 'node:fs'
import { join } from 'node:path'
import type { Agent, Finding, ScanContext } from '../types.js'
import { readText } from './config-parsers.js'

interface GitEntry {
  section: string
  key: string
  value: string
}

export function parseGitConfig(text: string): GitEntry[] {
  const entries: GitEntry[] = []
  let section = ''
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#') || line.startsWith(';')) continue
    const header = line.match(/^\[([^\s\]]+)(?:\s+"([^"]*)")?\]$/)
    if (header) {
      section = header[2] !== undefined ? `${header[1]!.toLowerCase()}.${header[2]}` : header[1]!.toLowerCase()
      continue
    }
    const eq = line.indexOf('=')
    if (eq === -1) continue
    const key = line.slice(0, eq).trim().toLowerCase()
    const value = line.slice(eq + 1).trim().replace(/^"|"$/g, '')
    entries.push({ section, key, value })
  }
  return entries
}

const RUNS_A_PROGRAM: Array<{ section: RegExp; key: RegExp; label: string }> = [
  { section: /^core$/, key: /^hookspath$/, label: 'core.hooksPath points git hooks at a directory the repo controls' },
  { section: /^core$/, key: /^sshcommand$/, label: 'core.sshCommand replaces ssh for every fetch and push' },
  { section: /^core$/, key: /^(pager|editor|askpass)$/, label: 'core.pager, editor or askpass names a program git will launch' },
  { section: /^core$/, key: /^gitproxy$/, label: 'core.gitProxy runs a program for every remote connection' },
  { section: /^alias$/, key: /./, label: 'a shell alias (starts with !) that runs when the alias is invoked' },
  { section: /^credential/, key: /^helper$/, label: 'a credential helper that runs a shell command' },
  { section: /^filter\./, key: /^(clean|smudge|process)$/, label: 'a clean or smudge filter that runs on checkout and add' },
  { section: /^diff\./, key: /^(textconv|command)$/, label: 'a diff driver that runs on every git diff' },
  { section: /^merge\./, key: /^driver$/, label: 'a merge driver that runs during merges' },
  { section: /^(include|includeif\.)/, key: /^path$/, label: 'an include that pulls config from another file' },
  { section: /^gpg/, key: /^program$/, label: 'gpg.program that runs on every signed commit' },
  { section: /^sequence$/, key: /^editor$/, label: 'sequence.editor that runs during rebase' },
  { section: /^uploadpack$/, key: /^packobjectshook$/, label: 'uploadpack.packObjectsHook that runs on fetch' },
]

function isFsmonitorCommand(value: string): boolean {
  const v = value.trim().toLowerCase()
  return v !== '' && v !== 'false' && v !== 'true' && v !== 'builtin' && v !== 'off' && v !== '0'
}

function describe(entry: GitEntry): string | undefined {
  if (entry.section === 'alias' && !entry.value.startsWith('!')) return undefined
  if (/^credential/.test(entry.section) && entry.key === 'helper' && !entry.value.startsWith('!')) return undefined
  for (const rule of RUNS_A_PROGRAM) {
    if (rule.section.test(entry.section) && rule.key.test(entry.key)) return rule.label
  }
  return undefined
}

function repoConfigFindings(ctx: ScanContext): Finding[] {
  const gitDir = join(ctx.project, '.git')
  const configPath = join(gitDir, 'config')
  const text = readText(configPath)
  if (text === undefined) return []
  const findings: Finding[] = []
  const entries = parseGitConfig(text)
  const short = configPath.replace(ctx.home, '~')

  const fsmonitor = entries.find((e) => e.section === 'core' && e.key === 'fsmonitor')
  if (fsmonitor && isFsmonitorCommand(fsmonitor.value)) {
    findings.push({
      category: 'git',
      severity: 'critical',
      title: 'Repository .git/config runs a command on every git status (GitSpawn)',
      detail: `${short} sets core.fsmonitor to "${fsmonitor.value.slice(0, 80)}". Every agent that runs git status or git diff in the background executes it, before any trust prompt and outside any sandbox. Unless you set this yourself, treat the repo as hostile and delete the key.`,
      path: configPath,
    })
  }

  const others = entries.map((e) => ({ e, label: describe(e) })).filter((x) => x.label !== undefined)
  for (const { e, label } of others) {
    findings.push({
      category: 'git',
      severity: 'high',
      title: `Repository .git/config names a program: ${e.section}.${e.key}`,
      detail: `${short} contains ${label}: "${e.value.slice(0, 80)}". Repository level config arrives with a clone and runs with your permissions the moment an agent touches git.`,
      path: configPath,
    })
  }

  const hooksDir = join(gitDir, 'hooks')
  if (existsSync(hooksDir)) {
    let active: string[] = []
    try {
      active = readdirSync(hooksDir).filter((f) => !f.endsWith('.sample') && statSync(join(hooksDir, f)).isFile())
    } catch {
      active = []
    }
    if (active.length > 0) {
      findings.push({
        category: 'git',
        severity: 'low',
        title: `${active.length} active git hook${active.length > 1 ? 's' : ''} in this repository`,
        detail: `${hooksDir.replace(ctx.home, '~')}: ${active.slice(0, 5).join(', ')}${active.length > 5 ? ` and ${active.length - 5} more` : ''}. Hooks run whenever an agent commits, pushes or checks out. Fine if you installed them, worth a look if you did not.`,
        path: hooksDir,
      })
    }
  }
  return findings
}

function globalConfigFindings(ctx: ScanContext): Finding[] {
  const paths = [join(ctx.home, '.gitconfig'), join(ctx.home, '.config', 'git', 'config')]
  const findings: Finding[] = []
  for (const path of paths) {
    const text = readText(path)
    if (text === undefined) continue
    const entries = parseGitConfig(text)
    const short = path.replace(ctx.home, '~')
    const fsmonitor = entries.find((e) => e.section === 'core' && e.key === 'fsmonitor')
    if (fsmonitor && isFsmonitorCommand(fsmonitor.value)) {
      findings.push({
        category: 'git',
        severity: 'medium',
        title: 'Global git config runs a custom fsmonitor command',
        detail: `${short} sets core.fsmonitor to "${fsmonitor.value.slice(0, 80)}". It runs on every git status in every repo, including inside agent sessions. Prefer core.fsmonitor = true, which uses the builtin daemon.`,
        path,
      })
    }
    const shellAliases = entries.filter((e) => e.section === 'alias' && e.value.startsWith('!'))
    if (shellAliases.length > 0) {
      findings.push({
        category: 'git',
        severity: 'info',
        title: `${shellAliases.length} git alias${shellAliases.length > 1 ? 'es' : ''} run${shellAliases.length > 1 ? '' : 's'} shell commands`,
        detail: `${short}: ${shellAliases.map((a) => a.key).slice(0, 6).join(', ')}. An agent allowed to run "git <alias>" is really running these shell commands.`,
        path,
      })
    }
  }
  return findings
}

interface Patch {
  slug: string
  fixed?: string
  note: string
}

const GITSPAWN: Patch[] = [
  { slug: 'claude-code', fixed: '2.1.196', note: 'core.fsmonitor path fixed in 2.1.196. A second config path used by ultrareview was still open at publication.' },
  { slug: 'codex', fixed: '0.131.0', note: 'affected 0.102.0 through 0.130.0, fixed in 0.131.0.' },
  { slug: 'goose', fixed: '1.44.0', note: 'fixed in 1.44.0.' },
  { slug: 'hermes', note: 'unpatched at publication (confirmed on 0.21.0).' },
  { slug: 'qwen-code', note: 'unpatched at publication (confirmed on 0.22.3).' },
  { slug: 'grok', note: 'unpatched at publication (confirmed on 1.0.13).' },
]

export function compareVersions(a: string, b: string): number {
  const pa = a.split(/[.-]/).map((x) => parseInt(x, 10))
  const pb = b.split(/[.-]/).map((x) => parseInt(x, 10))
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0
    const y = pb[i] ?? 0
    if (Number.isNaN(x) || Number.isNaN(y)) continue
    if (x !== y) return x < y ? -1 : 1
  }
  return 0
}

function agentVersionFindings(agents: Agent[]): Finding[] {
  const findings: Finding[] = []
  for (const agent of agents) {
    const patch = GITSPAWN.find((p) => p.slug === agent.slug)
    if (!patch) continue
    if (patch.fixed) {
      if (!agent.version || compareVersions(agent.version, patch.fixed) >= 0) continue
      findings.push({
        category: 'git',
        severity: 'high',
        title: `${agent.name} v${agent.version} is vulnerable to GitSpawn`,
        detail: `A cloned repo's .git/config can run code through core.fsmonitor when the agent calls git status. ${agent.name}: ${patch.note} Update to ${patch.fixed} or later.`,
        agent: agent.slug,
      })
      continue
    }
    findings.push({
      category: 'git',
      severity: 'medium',
      title: `${agent.name} had no GitSpawn fix when the flaw was published`,
      detail: `A cloned repo's .git/config can run code through core.fsmonitor when the agent calls git status. ${agent.name}: ${patch.note} Check the changelog for your version and inspect .git/config before opening unfamiliar repos.`,
      agent: agent.slug,
    })
  }
  return findings
}

export async function scanGit(ctx: ScanContext): Promise<Finding[]> {
  if (ctx.agents.length === 0) return []
  return [...repoConfigFindings(ctx), ...globalConfigFindings(ctx), ...agentVersionFindings(ctx.agents)]
}
