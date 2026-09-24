import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Finding, ScanContext, Severity } from '../types.js'
import { readJson } from './config-parsers.js'
import type { ShellPosture } from './shell.js'

interface SensitiveTarget {
  path: string
  label: string
  weight: 'critical' | 'high'
  detail: string
}

function targets(home: string): SensitiveTarget[] {
  return [
    { path: join(home, '.ssh'), label: 'SSH keys', weight: 'critical', detail: 'Private keys grant access to every server and git remote you use.' },
    { path: join(home, '.aws'), label: 'AWS credentials', weight: 'critical', detail: 'Access keys for your AWS accounts.' },
    { path: join(home, '.config', 'gcloud'), label: 'Google Cloud credentials', weight: 'critical', detail: 'OAuth tokens and service account keys for GCP.' },
    { path: join(home, '.azure'), label: 'Azure credentials', weight: 'critical', detail: 'Tokens for Azure subscriptions.' },
    { path: join(home, '.kube'), label: 'Kubernetes config', weight: 'high', detail: 'Cluster credentials and contexts.' },
    { path: join(home, '.gnupg'), label: 'GPG keys', weight: 'high', detail: 'Signing and decryption keys.' },
    { path: join(home, '.docker', 'config.json'), label: 'Docker registry credentials', weight: 'high', detail: 'Registry auth tokens.' },
    { path: join(home, '.config', 'gh', 'hosts.yml'), label: 'GitHub CLI token', weight: 'high', detail: 'OAuth token with repo scope for your GitHub account.' },
    { path: join(home, '.netrc'), label: '.netrc credentials', weight: 'high', detail: 'Plaintext logins for network services.' },
    { path: join(home, '.git-credentials'), label: 'Git credentials', weight: 'high', detail: 'Plaintext git remote passwords or tokens.' },
    { path: join(home, '.npmrc'), label: 'npm auth token', weight: 'high', detail: 'Publish rights for your npm packages.' },
    { path: join(home, '.pypirc'), label: 'PyPI credentials', weight: 'high', detail: 'Publish rights for your PyPI packages.' },
  ]
}

function isAncestorOrSelf(dir: string, target: string): boolean {
  const norm = (p: string) => p.replace(/[\\/]+$/, '')
  const d = norm(dir)
  const t = norm(target)
  return t === d || t.startsWith(d + '/') || t.startsWith(d + '\\')
}

export async function scanPermissions(ctx: ScanContext, posture: ShellPosture, unknownStdioServers: number): Promise<Finding[]> {
  if (ctx.agents.length === 0) return []
  const findings: Finding[] = []
  const { home } = ctx

  const state = readJson(join(home, '.claude.json')) as Record<string, unknown> | undefined
  const projects = state && typeof state['projects'] === 'object' && state['projects'] ? Object.keys(state['projects'] as Record<string, unknown>) : []
  const broad = projects.filter((p) => isAncestorOrSelf(p, home))
  if (broad.length > 0 && ctx.agents.some((a) => a.slug === 'claude-code')) {
    findings.push({
      category: 'file-access',
      severity: 'high',
      title: 'Claude Code has been run with your home directory as the project',
      detail: `~/.claude.json lists ${broad.join(', ')} as a project. Sessions started there treat every file under it, including credentials and other repos, as in scope and readable without a prompt.`,
      agent: 'claude-code',
    })
  }

  const settingsPaths = [join(home, '.claude', 'settings.json'), join(ctx.project, '.claude', 'settings.json'), join(ctx.project, '.claude', 'settings.local.json')]
  for (const path of settingsPaths) {
    const settings = readJson(path) as Record<string, unknown> | undefined
    const perms = settings?.['permissions'] as Record<string, unknown> | undefined
    const extra = Array.isArray(perms?.['additionalDirectories']) ? (perms!['additionalDirectories'] as unknown[]).filter((x): x is string => typeof x === 'string') : []
    const wide = extra.filter((d) => isAncestorOrSelf(d.replace(/^~/, home), home))
    if (wide.length > 0) {
      findings.push({ category: 'file-access', severity: 'high', title: 'Claude Code additionalDirectories includes your home directory', detail: `${path.replace(home, '~')} grants ${wide.join(', ')} to every session.`, path, agent: 'claude-code' })
    }
  }

  const exposure: 'unprompted' | 'mcp' | 'prompted' = posture.unprompted ? 'unprompted' : unknownStdioServers > 0 ? 'mcp' : 'prompted'
  const why =
    exposure === 'unprompted'
      ? `${posture.reasons[0]!}. Nothing stands between a prompt injection and these files`
      : exposure === 'mcp'
        ? `${unknownStdioServers} unrecognized MCP server${unknownStdioServers > 1 ? 's' : ''} run${unknownStdioServers > 1 ? '' : 's'} as a local process with your full permissions and no prompt`
        : 'agents prompt before shell commands, but any approved read or trusted MCP server can still reach it'

  for (const t of targets(home)) {
    if (!existsSync(t.path)) continue
    const severity: Severity =
      exposure === 'unprompted' ? t.weight : exposure === 'mcp' ? (t.weight === 'critical' ? 'high' : 'medium') : t.weight === 'critical' ? 'medium' : 'low'
    findings.push({
      category: 'file-access',
      severity,
      title: `${t.label} reachable by AI agents`,
      detail: `${t.detail} ${exposure === 'prompted' ? 'Exposure is limited because ' : ''}${why}.`,
      path: t.path,
    })
  }

  if (ctx.project === home.replace(/[\\/]+$/, '')) {
    findings.push({ category: 'file-access', severity: 'high', title: 'Scan directory is your home directory', detail: 'An agent started here treats your entire home directory as the project. Start agents inside a repo instead.', path: ctx.project })
  }

  return findings
}
