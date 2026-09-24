import { existsSync } from 'node:fs'
import { join } from 'node:path'
import type { Agent, Finding, ScanContext } from '../types.js'
import { readJson, readText, parseTomlSubset } from './config-parsers.js'

export interface ShellPosture {
  unprompted: boolean
  reasons: string[]
}

function rec(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === 'object' && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined
}

function strArr(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

function countHooks(hooks: unknown): number {
  const h = rec(hooks)
  if (!h) return 0
  let n = 0
  for (const entries of Object.values(h)) {
    if (!Array.isArray(entries)) continue
    for (const entry of entries) {
      const inner = rec(entry)
      const list = Array.isArray(inner?.['hooks']) ? (inner!['hooks'] as unknown[]) : [entry]
      n += list.filter((x) => rec(x)?.['type'] === 'command' || typeof rec(x)?.['command'] === 'string').length
    }
  }
  return n
}

function claudeCode(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const findings: Finding[] = []
  const files = [
    join(ctx.home, '.claude', 'settings.json'),
    join(ctx.project, '.claude', 'settings.json'),
    join(ctx.project, '.claude', 'settings.local.json'),
  ].filter((p) => existsSync(p))

  let promptsIntact = true
  for (const path of files) {
    const settings = rec(readJson(path))
    if (!settings) continue
    const short = path.replace(ctx.home, '~')
    const perms = rec(settings['permissions'])
    const mode = perms?.['defaultMode']
    const allow = strArr(perms?.['allow'])
    const bashAll = allow.filter((r) => /^Bash(\(\*?(:\*)?\))?$/.test(r.trim()))
    const bashRules = allow.filter((r) => r.startsWith('Bash('))
    const wildcardTools = allow.filter((r) => /^(Write|Edit|MultiEdit|NotebookEdit|WebFetch)(\(\*\))?$/.test(r.trim()))

    if (mode === 'bypassPermissions' || mode === 'dontAsk') {
      promptsIntact = false
      posture.unprompted = true
      posture.reasons.push(`Claude Code defaultMode is ${mode} in ${short}`)
      findings.push({
        category: 'shell',
        severity: 'high',
        title: `Claude Code runs without permission prompts (${mode})`,
        detail: `${short} sets permissions.defaultMode to "${mode}". Any instruction the model follows, including one injected through a README, issue, or web page, executes immediately.`,
        path,
        agent: agent.slug,
      })
    } else if (mode === 'acceptEdits') {
      findings.push({
        category: 'shell',
        severity: 'medium',
        title: 'Claude Code auto accepts file edits',
        detail: `${short} sets permissions.defaultMode to "acceptEdits". Writes anywhere in the working tree land without review.`,
        path,
        agent: agent.slug,
      })
    }

    if (bashAll.length > 0) {
      promptsIntact = false
      posture.unprompted = true
      posture.reasons.push(`Claude Code allow list includes ${bashAll[0]} in ${short}`)
      findings.push({
        category: 'shell',
        severity: 'high',
        title: 'Claude Code pre approves every shell command',
        detail: `${short} allow list contains "${bashAll[0]}". This is equivalent to bypass mode for the shell.`,
        path,
        agent: agent.slug,
      })
    } else if (bashRules.length > 0) {
      const risky = bashRules.filter((r) => /curl|wget|sudo|rm |chmod|ssh|scp|eval|bash -c|sh -c|npm publish|git push/.test(r))
      findings.push({
        category: 'shell',
        severity: risky.length > 0 ? 'medium' : 'info',
        title: `Claude Code pre approves ${bashRules.length} shell command pattern${bashRules.length > 1 ? 's' : ''}`,
        detail: `${short}: ${bashRules.slice(0, 6).join(', ')}${bashRules.length > 6 ? ` and ${bashRules.length - 6} more` : ''}${risky.length > 0 ? `. Patterns that can reach the network or escalate: ${risky.join(', ')}` : ''}`,
        path,
        agent: agent.slug,
      })
    }

    if (wildcardTools.length > 0) {
      findings.push({
        category: 'shell',
        severity: 'low',
        title: `Claude Code pre approves ${wildcardTools.join(', ')}`,
        detail: `${short} allows these tools without a prompt.`,
        path,
        agent: agent.slug,
      })
    }

    const hookCount = countHooks(settings['hooks'])
    if (hookCount > 0) {
      findings.push({
        category: 'shell',
        severity: path.includes(ctx.project) && !path.startsWith(ctx.home + '/.claude') ? 'medium' : 'low',
        title: `${hookCount} Claude Code hook${hookCount > 1 ? 's' : ''} run${hookCount > 1 ? '' : 's'} shell commands automatically`,
        detail: `${short} defines hooks that execute on session or tool events without a prompt. Project scoped hooks run for anyone who opens the repo.`,
        path,
        agent: agent.slug,
      })
    }

    if (settings['enableAllProjectMcpServers'] === true) {
      findings.push({
        category: 'shell',
        severity: 'medium',
        title: 'Claude Code auto trusts every project MCP server',
        detail: `${short} sets enableAllProjectMcpServers. Any .mcp.json in a cloned repo starts its servers without asking you.`,
        path,
        agent: agent.slug,
      })
    }

    const deny = strArr(perms?.['deny'])
    if (deny.length === 0 && path.startsWith(ctx.home + '/.claude')) {
      findings.push({
        category: 'shell',
        severity: 'low',
        title: 'Claude Code has no deny rules',
        detail: `${short} has no permissions.deny list. Add Read(./.env), Read(~/.ssh/**), Read(~/.aws/**) and similar so the model cannot read credentials even when asked.`,
        path,
        agent: agent.slug,
      })
    }
  }

  const state = rec(readJson(join(ctx.home, '.claude.json')))
  if (state?.['bypassPermissionsModeAccepted'] === true && promptsIntact) {
    findings.push({
      category: 'shell',
      severity: 'low',
      title: 'Claude Code bypass mode has been accepted on this machine',
      detail: '~/.claude.json records that --dangerously-skip-permissions was accepted at least once. Sessions started with that flag run every command unprompted.',
      agent: agent.slug,
    })
  }

  if (promptsIntact && findings.every((f) => f.severity === 'info' || f.severity === 'low')) {
    findings.push({
      category: 'shell',
      severity: 'info',
      title: 'Claude Code prompts before running commands',
      detail: 'Default permission mode is active. Shell commands outside the allow list ask first.',
      agent: agent.slug,
    })
  }
  return findings
}

function codex(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.codex', 'config.toml')
  const text = readText(path)
  if (text === undefined) {
    return [{ category: 'shell', severity: 'info', title: 'Codex CLI uses its default sandbox', detail: 'No ~/.codex/config.toml found. Defaults are workspace-write with approval on request.', agent: agent.slug }]
  }
  const toml = parseTomlSubset(text)
  const findings: Finding[] = []
  const approval = toml['approval_policy']
  const sandbox = toml['sandbox_mode']
  if (approval === 'never') {
    posture.unprompted = true
    posture.reasons.push('Codex approval_policy is never')
    findings.push({ category: 'shell', severity: 'high', title: 'Codex CLI never asks for approval', detail: `${path.replace(ctx.home, '~')} sets approval_policy = "never". Commands run without confirmation.`, path, agent: agent.slug })
  }
  if (sandbox === 'danger-full-access') {
    posture.unprompted = true
    posture.reasons.push('Codex sandbox_mode is danger-full-access')
    findings.push({ category: 'shell', severity: 'high', title: 'Codex CLI sandbox is disabled', detail: `${path.replace(ctx.home, '~')} sets sandbox_mode = "danger-full-access". Commands can write anywhere and reach the network.`, path, agent: agent.slug })
  }
  if (findings.length === 0) {
    findings.push({ category: 'shell', severity: 'info', title: `Codex CLI sandbox: ${String(sandbox ?? 'default')}, approval: ${String(approval ?? 'default')}`, detail: 'Sandbox and approval policy are not set to their most permissive values.', path, agent: agent.slug })
  }
  return findings
}

function gemini(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.gemini', 'settings.json')
  const settings = rec(readJson(path))
  const tools = rec(settings?.['tools'])
  const autoAccept = settings?.['autoAccept'] === true || tools?.['autoAccept'] === true
  const yolo = rec(settings?.['general'])?.['yolo'] === true
  if (yolo) {
    posture.unprompted = true
    posture.reasons.push('Gemini CLI yolo mode is enabled')
    return [{ category: 'shell', severity: 'high', title: 'Gemini CLI runs in YOLO mode', detail: `${path.replace(ctx.home, '~')} enables yolo. Every tool call, including shell, is auto approved.`, path, agent: agent.slug }]
  }
  if (autoAccept) {
    return [{ category: 'shell', severity: 'medium', title: 'Gemini CLI auto accepts tool calls', detail: `${path.replace(ctx.home, '~')} sets autoAccept. Read only tools run without a prompt; check whether shell is included in your version.`, path, agent: agent.slug }]
  }
  return [{ category: 'shell', severity: 'info', title: 'Gemini CLI prompts before running commands', detail: 'No auto accept or yolo settings found.', agent: agent.slug }]
}

function generic(agent: Agent, severity: Finding['severity'], detail: string): Finding {
  return { category: 'shell', severity, title: `${agent.name} can run shell commands`, detail, agent: agent.slug }
}

export async function scanShell(ctx: ScanContext): Promise<{ findings: Finding[]; posture: ShellPosture }> {
  const posture: ShellPosture = { unprompted: false, reasons: [] }
  const findings: Finding[] = []

  if (typeof process.getuid === 'function' && process.getuid() === 0) {
    posture.unprompted = true
    posture.reasons.push('snuf is running as root, so agents launched from this shell are too')
    findings.push({ category: 'shell', severity: 'critical', title: 'Running as root', detail: 'This scan is running as root. AI agents launched from this account can modify any file on the system.' })
  }

  for (const agent of ctx.agents) {
    switch (agent.slug) {
      case 'claude-code':
        findings.push(...claudeCode(agent, ctx, posture))
        break
      case 'codex':
        findings.push(...codex(agent, ctx, posture))
        break
      case 'gemini-cli':
        findings.push(...gemini(agent, ctx, posture))
        break
      case 'cursor':
      case 'windsurf':
      case 'kiro':
      case 'trae':
      case 'zed':
        findings.push(generic(agent, 'low', `${agent.name} has an integrated terminal and an auto run setting stored in its app state, which snuf cannot read. Check the agent settings for auto run or turbo mode.`))
        break
      case 'aider':
        findings.push(generic(agent, 'low', 'Aider runs lint and test commands automatically when configured with auto-lint or auto-test.'))
        break
      case 'openclaw':
        findings.push(generic(agent, 'medium', 'OpenClaw executes skills and tools as a long running process with your user permissions. Review installed skills under ~/.openclaw.'))
        break
      case 'claude-desktop':
        break
      default:
        findings.push(generic(agent, 'low', `${agent.name} is installed. Verify its command approval settings.`))
    }
  }

  return { findings, posture }
}
