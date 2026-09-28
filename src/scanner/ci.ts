import { join } from 'node:path'
import fg from 'fast-glob'
import type { Finding, ScanContext } from '../types.js'
import { readText } from './config-parsers.js'

interface AgentAction {
  pattern: RegExp
  agent: string
  label: string
}

const AGENT_ACTIONS: AgentAction[] = [
  { pattern: /anthropics\/claude-code-(base-)?action/i, agent: 'claude-code', label: 'Claude Code' },
  { pattern: /openai\/codex-action/i, agent: 'codex', label: 'Codex' },
  { pattern: /google-github-actions\/run-gemini-cli|google-gemini\/gemini-cli-action/i, agent: 'gemini-cli', label: 'Gemini CLI' },
  { pattern: /github\/copilot-(cli-)?action|copilot-coding-agent/i, agent: 'copilot', label: 'Copilot' },
  { pattern: /aider-ai\/aider-action|mirrajabi\/aider-github-action/i, agent: 'aider', label: 'Aider' },
  { pattern: /sst\/opencode\/github|opencode-ai\/opencode-action/i, agent: 'opencode', label: 'OpenCode' },
]

const UNTRUSTED_TRIGGERS = ['issues', 'issue_comment', 'pull_request_target', 'pull_request_review', 'pull_request_review_comment', 'discussion', 'discussion_comment']
const UNTRUSTED_FIELDS = /github\.event\.(issue|comment|pull_request|review|discussion)\.(title|body)/

function triggers(text: string): string[] {
  const onLine = text.match(/^on:[ \t]*([^\n#]+)$/m)
  if (onLine && onLine[1]!.trim()) {
    return onLine[1]!.replace(/[[\]]/g, '').split(',').map((s) => s.trim()).filter(Boolean)
  }
  const block = text.match(/^on:[ \t]*\n((?:[ \t]+.*\n?)+)/m)
  if (!block) return []
  const found: string[] = []
  for (const line of block[1]!.split('\n')) {
    const m = line.match(/^\s{2}(?:-\s*)?([a-z_]+):?\s*$/)
    if (m) found.push(m[1]!)
  }
  return found
}

function usesLine(text: string, action: AgentAction): { ref: string; floating: boolean } | undefined {
  const m = text.match(new RegExp(`uses:\\s*["']?(${action.pattern.source})(@([^\\s"'#]+))?`, 'i'))
  if (!m) return undefined
  const ref = m[m.length - 1] ?? ''
  const floating = ref === '' || !/^[0-9a-f]{40}$/i.test(ref)
  return { ref, floating }
}

function scanWorkflow(path: string, ctx: ScanContext): Finding[] {
  const text = readText(path)
  if (text === undefined) return []
  const short = path.replace(ctx.project, '.')
  const findings: Finding[] = []
  const on = triggers(text)
  const untrusted = on.filter((t) => UNTRUSTED_TRIGGERS.includes(t))
  const readsEventText = UNTRUSTED_FIELDS.test(text)
  const secretRefs = [...new Set([...text.matchAll(/secrets\.([A-Z0-9_]+)/g)].map((m) => m[1]!))].filter((s) => s !== 'GITHUB_TOKEN')
  const writePerms = [...text.matchAll(/^\s*(contents|id-token|packages|actions|deployments|pull-requests|issues):\s*write\s*$/gm)].map((m) => m[1]!)
  const openToAll = /allowed_non_write_users:\s*["']?\*/.test(text)

  for (const action of AGENT_ACTIONS) {
    const used = usesLine(text, action)
    if (!used) continue

    if (openToAll) {
      findings.push({
        category: 'ci',
        severity: 'high',
        title: `${action.label} workflow lets anyone on GitHub drive the agent`,
        detail: `${short} sets allowed_non_write_users: "*". Any account can open an issue or comment that becomes the agent's prompt. This was the exact configuration behind the June 2026 Claude Code Action secret exposure.${secretRefs.length ? ` Secrets in reach: ${secretRefs.slice(0, 5).join(', ')}.` : ''}`,
        path,
        agent: action.agent,
      })
    } else if (untrusted.length > 0 || readsEventText) {
      const dangerous = writePerms.filter((p) => p === 'contents' || p === 'id-token')
      findings.push({
        category: 'ci',
        severity: dangerous.length > 0 || secretRefs.length > 0 ? 'medium' : 'low',
        title: `${action.label} runs in CI on untrusted issue or PR text`,
        detail: `${short} triggers on ${untrusted.join(', ') || 'event payload text'}. Issue titles, bodies and comments from strangers become agent input.${dangerous.length ? ` The job has ${dangerous.join(' and ')}: write.` : ''}${secretRefs.length ? ` Secrets in reach: ${secretRefs.slice(0, 5).join(', ')}.` : ''} Gate on the actor, keep permissions read only, and pass no more secrets than the model needs.`,
        path,
        agent: action.agent,
      })
    }

    if (used.floating) {
      findings.push({
        category: 'ci',
        severity: 'low',
        title: `${action.label} action is not pinned to a commit`,
        detail: `${short} uses ${used.ref ? `@${used.ref}` : 'no ref'}. A tag or branch can be moved to new code without you noticing. Pin to a full commit SHA.`,
        path,
        agent: action.agent,
      })
    }
  }
  return findings
}

export async function scanCi(ctx: ScanContext): Promise<Finding[]> {
  const dir = join(ctx.project, '.github', 'workflows')
  let files: string[] = []
  try {
    files = fg.sync('*.{yml,yaml}', { cwd: dir, absolute: true, onlyFiles: true, suppressErrors: true })
  } catch {
    return []
  }
  const findings: Finding[] = []
  for (const file of files) {
    const own = scanWorkflow(file, ctx)
    findings.push(...own.filter((f) => !ctx.options.agent || f.agent === ctx.options.agent))
  }
  return findings
}
