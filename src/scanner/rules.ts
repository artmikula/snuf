import { existsSync, statSync } from 'node:fs'
import { join } from 'node:path'
import fg from 'fast-glob'
import type { Finding, ScanContext } from '../types.js'
import { readText } from './config-parsers.js'
import { compareVersions } from './git.js'

interface RuleFile {
  path: string
  agent: string
  scope: 'user' | 'project'
}

const ZERO_WIDTH = /[​-‏⁠-⁤﻿‪-‮⁦-⁩]|[\u{E0000}-\u{E007F}]/u
const INJECTION = /(ignore (all |any )?(previous|prior|above) instructions|do not (tell|inform|mention|reveal)( this)? to the user|without (asking|telling|informing) the user|hide this from the user|system prompt override|you are now in developer mode|(before|after) (every|each) (task|response|command)[^\n]{0,80}(send|post|upload|read))/i
const CREDENTIAL_PATH = /(~|\$HOME|\/Users\/[^/\s]+|\/home\/[^/\s]+)\/\.(ssh|aws|gnupg|kube|netrc|git-credentials|npmrc|pypirc|config\/gh|docker\/config\.json)|\bid_(rsa|ed25519|ecdsa)\b|\.aws\/credentials|\.claude\/\.credentials|shell history|\.(bash|zsh)_history/gi
const SENDS_OUT = /\b(post|send|upload|submit|transmit|exfiltrate|forward)\b[^\n]{0,120}(https?:\/\/|webhook|endpoint|url)|\bcurl\b[^\n]*(-d |--data|-F |-T |--upload-file|-X ?POST)/gi

function credentialExfil(text: string): { cred: string; send: string } | undefined {
  const sends = [...text.matchAll(SENDS_OUT)]
  if (sends.length === 0) return undefined
  for (const cred of text.matchAll(CREDENTIAL_PATH)) {
    const near = sends.find((s) => Math.abs((s.index ?? 0) - (cred.index ?? 0)) < 400)
    if (near) return { cred: cred[0], send: near[0].slice(0, 60).trim() }
  }
  return undefined
}
const DOWNLOADS = /\b(curl|wget|Invoke-WebRequest|iwr|fetch)\b[^\n]*https?:\/\//i
const PIPE_TO_SHELL = /\|\s*(sudo\s+)?(ba|z)?sh\b/
const DANGEROUS = /\b(rm -rf|sudo |chmod \+x|chmod 777|base64 (-d|--decode)|eval\s*\(|nc -e|mkfifo|\/dev\/tcp\/|crontab|launchctl|systemctl enable|ssh-keygen|cat ~\/\.ssh|\.aws\/credentials|~\/\.netrc)/i
const WRITES_OUTSIDE = /(\s|^)(cp|mv|tee|echo [^\n]*>)\s+[^\n]*(~\/\.|\/etc\/|\/usr\/|\$HOME\/\.)/

function ruleFiles(ctx: ScanContext): RuleFile[] {
  const { home, project } = ctx
  const fixed: RuleFile[] = [
    { path: join(home, '.claude', 'CLAUDE.md'), agent: 'claude-code', scope: 'user' },
    { path: join(home, '.codex', 'AGENTS.md'), agent: 'codex', scope: 'user' },
    { path: join(home, '.gemini', 'GEMINI.md'), agent: 'gemini-cli', scope: 'user' },
    { path: join(home, '.config', 'opencode', 'AGENTS.md'), agent: 'opencode', scope: 'user' },
    { path: join(home, '.openclaw', 'workspace', 'SOUL.md'), agent: 'openclaw', scope: 'user' },
    { path: join(home, '.openclaw', 'workspace', 'AGENTS.md'), agent: 'openclaw', scope: 'user' },
    { path: join(home, '.openclaw', 'workspace', 'MEMORY.md'), agent: 'openclaw', scope: 'user' },
    { path: join(home, '.hermes', 'SOUL.md'), agent: 'hermes', scope: 'user' },
    { path: join(home, '.factory', 'AGENTS.md'), agent: 'factory', scope: 'user' },
    { path: join(home, '.pi', 'agent', 'AGENTS.md'), agent: 'pi', scope: 'user' },
    { path: join(home, '.kimi-code', 'AGENTS.md'), agent: 'kimi-code', scope: 'user' },
    { path: join(home, '.grok', 'GROK.md'), agent: 'grok', scope: 'user' },
    { path: join(project, 'CLAUDE.md'), agent: 'claude-code', scope: 'project' },
    { path: join(project, '.claude', 'CLAUDE.md'), agent: 'claude-code', scope: 'project' },
    { path: join(project, 'CLAUDE.local.md'), agent: 'claude-code', scope: 'project' },
    { path: join(project, 'AGENTS.md'), agent: 'shared', scope: 'project' },
    { path: join(project, 'GEMINI.md'), agent: 'gemini-cli', scope: 'project' },
    { path: join(project, 'QWEN.md'), agent: 'qwen-code', scope: 'project' },
    { path: join(project, '.cursorrules'), agent: 'cursor', scope: 'project' },
    { path: join(project, '.windsurfrules'), agent: 'windsurf', scope: 'project' },
    { path: join(project, '.clinerules'), agent: 'cline', scope: 'project' },
    { path: join(project, '.github', 'copilot-instructions.md'), agent: 'copilot', scope: 'project' },
    { path: join(project, '.junie', 'guidelines.md'), agent: 'junie', scope: 'project' },
    { path: join(project, '.goosehints'), agent: 'goose', scope: 'project' },
    { path: join(project, 'GROK.md'), agent: 'grok', scope: 'project' },
    { path: join(project, '.factory', 'AGENTS.md'), agent: 'factory', scope: 'project' },
  ]
  const patterns: Array<[string, string, string, RuleFile['scope']]> = [
    [project, '.cursor/rules/**/*.{mdc,md}', 'cursor', 'project'],
    [project, '.windsurf/rules/**/*.md', 'windsurf', 'project'],
    [project, '.clinerules/**/*.md', 'cline', 'project'],
    [project, '.roo/rules*/**/*.md', 'roo-code', 'project'],
    [project, '.kiro/steering/**/*.md', 'kiro', 'project'],
    [project, '.trae/rules/**/*.md', 'trae', 'project'],
    [project, '.github/instructions/**/*.md', 'copilot', 'project'],
    [project, '.claude/skills/*/SKILL.md', 'claude-code', 'project'],
    [project, '.claude/commands/**/*.md', 'claude-code', 'project'],
    [project, '.claude/agents/**/*.md', 'claude-code', 'project'],
    [home, '.claude/skills/*/SKILL.md', 'claude-code', 'user'],
    [home, '.claude/commands/**/*.md', 'claude-code', 'user'],
    [home, '.claude/agents/**/*.md', 'claude-code', 'user'],
    [home, '.claude/plugins/*/skills/*/SKILL.md', 'claude-code', 'user'],
    [home, '.claude/plugins/cache/*/*/*/skills/*/SKILL.md', 'claude-code', 'user'],
    [home, '.claude/plugins/marketplaces/*/plugins/*/skills/*/SKILL.md', 'claude-code', 'user'],
    [home, '.agents/skills/*/SKILL.md', 'shared', 'user'],
    [project, '.agents/skills/*/SKILL.md', 'shared', 'project'],
    [home, '.codex/skills/*/SKILL.md', 'codex', 'user'],
    [home, '.openclaw/skills/*/SKILL.md', 'openclaw', 'user'],
    [home, '.openclaw/workspace/skills/*/SKILL.md', 'openclaw', 'user'],
    [home, '.factory/droids/**/*.md', 'factory', 'user'],
    [home, '.factory/commands/**/*.md', 'factory', 'user'],
    [project, '.factory/droids/**/*.md', 'factory', 'project'],
    [home, '.grok/skills/*/SKILL.md', 'grok', 'user'],
    [home, '.pi/agent/skills/*/SKILL.md', 'pi', 'user'],
    [home, '.hermes/skills/*/SKILL.md', 'hermes', 'user'],
    [home, '.kimi-code/skills/*/SKILL.md', 'kimi-code', 'user'],
  ]
  const files = fixed.filter((f) => existsSync(f.path) && statSync(f.path).isFile())
  for (const [cwd, pattern, agent, scope] of patterns) {
    try {
      for (const p of fg.sync(pattern, { cwd, absolute: true, dot: true, onlyFiles: true, followSymbolicLinks: false, suppressErrors: true })) {
        files.push({ path: p, agent, scope })
      }
    } catch {
      // unreadable directory, skip
    }
  }
  return latestPluginVersionsOnly(files)
}

const PLUGIN_CACHE = /^(.*\/\.claude\/plugins\/cache\/[^/]+\/[^/]+\/)([^/]+)\//

function latestPluginVersionsOnly(files: RuleFile[]): RuleFile[] {
  const latest = new Map<string, string>()
  for (const f of files) {
    const m = f.path.match(PLUGIN_CACHE)
    if (!m) continue
    const current = latest.get(m[1]!)
    if (!current || compareVersions(m[2]!, current) > 0) latest.set(m[1]!, m[2]!)
  }
  return files.filter((f) => {
    const m = f.path.match(PLUGIN_CACHE)
    return !m || latest.get(m[1]!) === m[2]
  })
}

interface Inspection {
  findings: Finding[]
  downloads: string[]
  privileged: Array<{ file: RuleFile; match: string }>
}

function inspect(file: RuleFile, home: string, acc: Inspection): void {
  const text = readText(file.path, 512_000)
  if (text === undefined) return
  const short = file.path.replace(home, '~')
  const isSkill = /SKILL\.md$|\/commands\/|\/agents\//.test(file.path)
  const kind = isSkill ? 'Skill' : 'Rules file'

  if (ZERO_WIDTH.test(text)) {
    acc.findings.push({ category: 'rules', severity: 'high', title: `${kind} contains invisible Unicode characters`, detail: `${short} contains zero width or bidirectional control characters. They can hide instructions from a human reader while the model still follows them. This is the rules file backdoor technique.`, path: file.path, agent: file.agent })
  }
  if (INJECTION.test(text)) {
    acc.findings.push({ category: 'rules', severity: 'high', title: `${kind} contains prompt injection phrasing`, detail: `${short} matched "${text.match(INJECTION)?.[0]}". Instructions that tell the model to hide actions from you or override earlier instructions have no place in a rules file.`, path: file.path, agent: file.agent })
  }
  const exfil = credentialExfil(text)
  if (exfil) {
    acc.findings.push({ category: 'rules', severity: 'high', title: `${kind} reads credentials and sends data to a remote endpoint`, detail: `${short} mentions ${exfil.cred} within a few lines of sending data out ("${exfil.send}"). Three lines of plain English in a skill are enough to exfiltrate a key. No code needed, so code scanners miss it.`, path: file.path, agent: file.agent })
  }
  if (PIPE_TO_SHELL.test(text) || (DOWNLOADS.test(text) && DANGEROUS.test(text))) {
    acc.findings.push({ category: 'rules', severity: 'high', title: `${kind} pipes downloads into a shell`, detail: `${short} contains a download piped into sh or bash, or a download next to privileged commands. The model will run it when the instruction applies.`, path: file.path, agent: file.agent })
  } else if (DOWNLOADS.test(text)) {
    acc.downloads.push(short)
  }
  if (DANGEROUS.test(text)) {
    acc.privileged.push({ file, match: text.match(DANGEROUS)?.[0] ?? '' })
  }
  if (WRITES_OUTSIDE.test(text)) {
    acc.findings.push({ category: 'rules', severity: 'medium', title: `${kind} writes outside the project`, detail: `${short} contains "${text.match(WRITES_OUTSIDE)?.[0]?.trim()}"`, path: file.path, agent: file.agent })
  }
}

function list(items: string[], max = 4): string {
  return `${items.slice(0, max).join(', ')}${items.length > max ? ` and ${items.length - max} more` : ''}`
}

export async function scanRules(ctx: ScanContext): Promise<{ findings: Finding[]; fileCount: number }> {
  const files = ruleFiles(ctx).filter((f) => !ctx.options.agent || f.agent === ctx.options.agent || f.agent === 'shared')
  const acc: Inspection = { findings: [], downloads: [], privileged: [] }
  const seen = new Set<string>()
  for (const file of files) {
    if (seen.has(file.path)) continue
    seen.add(file.path)
    inspect(file, ctx.home, acc)
  }
  const findings = acc.findings
  if (acc.downloads.length > 0) {
    findings.push({
      category: 'rules',
      severity: 'low',
      title: `${acc.downloads.length} rules or skill file${acc.downloads.length > 1 ? 's' : ''} instruct the agent to fetch from the network`,
      detail: `${list(acc.downloads)}. Network fetches in instructions are normal for installer style skills, but each one is a place where remote content becomes agent input.`,
    })
  }
  const projectPriv = acc.privileged.filter((p) => p.file.scope === 'project')
  if (acc.privileged.length > 0) {
    findings.push({
      category: 'rules',
      severity: projectPriv.length > 0 ? 'medium' : 'low',
      title: `${acc.privileged.length} rules or skill file${acc.privileged.length > 1 ? 's' : ''} reference privileged commands`,
      detail: `${list(acc.privileged.map((p) => `${p.file.path.replace(ctx.home, '~')} (${p.match.trim()})`))}. ${projectPriv.length > 0 ? 'Project scoped rules apply to anyone who clones the repo.' : 'User scoped, applies to all your sessions.'}`,
    })
  }
  if (files.length > 0 && ctx.agents.length > 0) {
    const skills = files.filter((f) => /SKILL\.md$/.test(f.path)).length
    findings.push({
      category: 'rules',
      severity: 'info',
      title: `${files.length} rules and skill file${files.length > 1 ? 's' : ''} shape agent behavior${skills ? ` (${skills} skills)` : ''}`,
      detail: 'Agents follow these before anything you type. Review them like code, especially ones that arrived with a cloned repo or a plugin.',
    })
  }
  return { findings, fileCount: files.length }
}
