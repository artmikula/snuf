import type { Agent, Finding, FindingCategory } from '../types.js'
import { compareVersions } from './git.js'

interface Advisory {
  slug: string
  fixed: string
  category: FindingCategory
  title: string
  detail: string
}

interface Unpatched {
  slug: string
  category: FindingCategory
  title: string
  detail: string
}

export const ADVISORIES: Advisory[] = [
  {
    slug: 'claude-code',
    fixed: '2.1.196',
    category: 'git',
    title: 'is vulnerable to GitSpawn',
    detail: "A cloned repo's .git/config can run code through core.fsmonitor when Claude Code calls git status. Fixed in 2.1.196. A second config path used by ultrareview was still open at publication.",
  },
  {
    slug: 'claude-code',
    fixed: '2.1.128',
    category: 'shell',
    title: 'can leak CI secrets through /proc reads',
    detail: 'Before 2.1.128 the Read tool could open sensitive /proc files, which the June 2026 Claude Code Action advisory chained into secret exfiltration from untrusted issues.',
  },
  {
    slug: 'claude-code',
    fixed: '2.1.91',
    category: 'shell',
    title: 'has known command injection bugs',
    detail: 'CVE-2026-35020, 35021 and 35022 are command validator bypasses that chain into credential exfiltration. Fixed by 2.1.91.',
  },
  {
    slug: 'codex',
    fixed: '0.131.0',
    category: 'git',
    title: 'is vulnerable to GitSpawn',
    detail: "A cloned repo's .git/config can run code through core.fsmonitor when Codex calls git status. Affected 0.102.0 through 0.130.0, fixed in 0.131.0.",
  },
  {
    slug: 'codex',
    fixed: '0.23.0',
    category: 'shell',
    title: 'runs project .codex/config.toml without asking',
    detail: 'CVE-2025-61260 (CVSS 9.8): before 0.23.0 Codex loaded project local config and .env, so a cloned repo could execute commands on first run.',
  },
  {
    slug: 'goose',
    fixed: '1.44.0',
    category: 'git',
    title: 'is vulnerable to GitSpawn',
    detail: "A cloned repo's .git/config can run code through core.fsmonitor when Goose calls git status. Fixed in 1.44.0.",
  },
  {
    slug: 'cursor',
    fixed: '3.0.0',
    category: 'shell',
    title: 'has unpatched remote code execution bugs',
    detail: 'Cursor 3.0 (April 2026) fixed CVE-2026-48124 (workspace .claude/settings.local.json hooks ran without approval) and the DuneSlide zero click prompt injection sandbox escapes CVE-2026-50548 and 50549.',
  },
]

export const UNPATCHED: Unpatched[] = [
  { slug: 'hermes', category: 'git', title: 'had no GitSpawn fix when the flaw was published', detail: 'Hermes hardens its own git calls with a noninteractive env, but four call sites missed it (issue #126017). Confirmed exploitable on 0.21.0 at publication.' },
  { slug: 'qwen-code', category: 'git', title: 'had no GitSpawn fix when the flaw was published', detail: '0.21.9 added a confirmation for repos whose config runs external programs, but Manifold still reproduced the attack on 0.22.3.' },
  { slug: 'grok', category: 'git', title: 'had no GitSpawn fix when the flaw was published', detail: 'Confirmed exploitable on 1.0.13 at publication.' },
]

export function advisoryFindings(agents: Agent[]): Finding[] {
  const findings: Finding[] = []
  for (const agent of agents) {
    const behind = ADVISORIES.filter((a) => a.slug === agent.slug && agent.version && compareVersions(agent.version, a.fixed) < 0)
    for (const a of behind) {
      findings.push({
        category: a.category,
        severity: 'high',
        title: `${agent.name} v${agent.version} ${a.title}`,
        detail: `${a.detail} Update to ${a.fixed} or later.`,
        agent: agent.slug,
      })
    }
    for (const u of UNPATCHED.filter((x) => x.slug === agent.slug)) {
      findings.push({
        category: u.category,
        severity: 'medium',
        title: `${agent.name} ${u.title}`,
        detail: `${u.detail} Inspect .git/config before opening unfamiliar repos and check the changelog for your version.`,
        agent: agent.slug,
      })
    }
  }
  return findings
}
