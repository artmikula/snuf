import { existsSync } from 'node:fs'
import { join, dirname } from 'node:path'
import type { Agent, Finding, ScanContext } from '../types.js'
import fg from 'fast-glob'
import { readJson, readText, parseTomlSubset } from './config-parsers.js'
import { compareVersions } from './git.js'

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
  const sandboxOn = files.some((p) => rec(rec(readJson(p))?.['sandbox'])?.['enabled'] === true)
  for (const path of files) {
    const settings = rec(readJson(path))
    if (!settings) continue
    const short = path.replace(ctx.home, '~')
    const perms = rec(settings['permissions'])
    const mode = perms?.['defaultMode']
    findings.push(...claudeSandbox(agent, settings, path, short))
    const allow = strArr(perms?.['allow'])
    const bashAll = allow.filter((r) => /^Bash(\(\*?(:\*)?\))?$/.test(r.trim()))
    const bashRules = allow.filter((r) => r.startsWith('Bash('))
    const wildcardTools = allow.filter((r) => /^(Write|Edit|MultiEdit|NotebookEdit|WebFetch)(\(\*\)|\(domain:\*\))?$/.test(r.trim()))
    const wholeMcpServers = allow.map((r) => r.trim().match(/^mcp__((?:(?!__)[^(\s])+)(__\*)?$/)?.[1]).filter((s): s is string => Boolean(s))
    if (wholeMcpServers.length > 0) {
      findings.push({
        category: 'shell',
        severity: 'low',
        title: `Claude Code pre approves every tool on ${wholeMcpServers.length} MCP server${wholeMcpServers.length > 1 ? 's' : ''}`,
        detail: `${short} allows mcp__${wholeMcpServers.slice(0, 4).join(', mcp__')}${wholeMcpServers.length > 4 ? ' and more' : ''} without a prompt. Any tool those servers add later, including after an update, is approved too.`,
        path,
        agent: agent.slug,
      })
    }
    const hardened = [
      perms?.['disableBypassPermissionsMode'] === 'disable' ? 'bypass mode disabled' : null,
      perms?.['disableAutoMode'] === 'disable' ? 'auto mode disabled' : null,
      perms?.['blockReadsOutsideWorkingDirectories'] === true ? 'reads fenced to working directories' : null,
    ].filter((x): x is string => x !== null)
    if (hardened.length > 0) {
      findings.push({ category: 'shell', severity: 'info', title: `Claude Code is hardened: ${hardened.join(', ')}`, detail: `${short} sets these under permissions. Good.`, path, agent: agent.slug })
    }

    if (mode === 'bypassPermissions' || mode === 'dontAsk') {
      promptsIntact = false
      posture.unprompted = true
      posture.reasons.push(`Claude Code defaultMode is ${mode} in ${short}`)
      findings.push({
        category: 'shell',
        severity: sandboxOn ? 'medium' : 'high',
        title: `Claude Code runs without permission prompts (${mode})`,
        detail: `${short} sets permissions.defaultMode to "${mode}". Any instruction the model follows, including one injected through a README, issue, or web page, executes immediately.${sandboxOn ? ' The Bash sandbox is on, which contains shell commands but not the other tools.' : ''}`,
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

function claudeSandbox(agent: Agent, settings: Record<string, unknown>, path: string, short: string): Finding[] {
  const sandbox = rec(settings['sandbox'])
  if (!sandbox) return []
  const findings: Finding[] = []
  const network = rec(sandbox['network'])
  const credentials = rec(sandbox['credentials'])
  if (sandbox['enabled'] === true) {
    const escape = sandbox['allowUnsandboxedCommands'] !== false
    findings.push({ category: 'shell', severity: escape ? 'low' : 'info', title: escape ? 'Claude Code sandbox is on, with the unsandboxed escape hatch open' : 'Claude Code sandbox is on and locked', detail: `${short} enables the Bash sandbox. ${escape ? 'allowUnsandboxedCommands is not set to false, so a command that fails inside the sandbox can be retried outside it with dangerouslyDisableSandbox.' : 'Commands that fail under the sandbox stay blocked.'}`, path, agent: agent.slug })
  }
  const excluded = strArr(sandbox['excludedCommands'])
  const riskyExcluded = excluded.filter((c) => /curl|wget|ssh|scp|sudo|bash|sh$|python|node|npx|docker|\*/.test(c))
  if (riskyExcluded.length > 0) {
    findings.push({ category: 'shell', severity: 'medium', title: `${riskyExcluded.length} command${riskyExcluded.length > 1 ? 's' : ''} excluded from the Claude Code sandbox`, detail: `${short} sandbox.excludedCommands lets ${riskyExcluded.slice(0, 5).join(', ')} run with no filesystem or network isolation.`, path, agent: agent.slug })
  }
  const domains = strArr(network?.['allowedDomains'])
  if (domains.some((d) => d === '*' || d === '*.*')) {
    findings.push({ category: 'shell', severity: 'medium', title: 'Claude Code sandbox allows every network domain', detail: `${short} sandbox.network.allowedDomains contains a wildcard, so the network isolation does nothing.`, path, agent: agent.slug })
  }
  if (credentials?.['allowPlaintextInject'] === true) {
    findings.push({ category: 'shell', severity: 'medium', title: 'Claude Code sandbox injects credentials in plaintext', detail: `${short} sets sandbox.credentials.allowPlaintextInject, so masked tokens are handed to sandboxed commands in the clear.`, path, agent: agent.slug })
  }
  if (sandbox['enableWeakerNestedSandbox'] === true) {
    findings.push({ category: 'shell', severity: 'low', title: 'Claude Code uses the weaker nested sandbox', detail: `${short} sets sandbox.enableWeakerNestedSandbox. Isolation inside containers is reduced.`, path, agent: agent.slug })
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
  if (toml['approvals_reviewer'] === 'auto_review') {
    findings.push({ category: 'shell', severity: 'medium', title: 'Codex CLI reviews its own approval requests', detail: `${path.replace(ctx.home, '~')} sets approvals_reviewer = "auto_review". The model decides whether to grant the sandbox escalations it asked for. You are only shown the result.`, path, agent: agent.slug })
  }
  if (sandbox !== 'danger-full-access' && rec(toml['sandbox_workspace_write'])?.['network_access'] === true) {
    findings.push({ category: 'shell', severity: 'medium', title: 'Codex CLI sandbox allows network access', detail: `${path.replace(ctx.home, '~')} sets sandbox_workspace_write.network_access = true. Commands can reach the internet without an approval prompt, which is what an exfiltration needs.`, path, agent: agent.slug })
  }
  const projects = rec(toml['projects'])
  if (projects) {
    const home = ctx.home.replace(/[\\/]+$/, '')
    const trustedHome = Object.entries(projects).filter(([p, v]) => rec(v)?.['trust_level'] === 'trusted' && (p.replace(/[\\/]+$/, '') === home || home.startsWith(p.replace(/[\\/]+$/, '') + '/')))
    if (trustedHome.length > 0) {
      findings.push({ category: 'shell', severity: 'high', title: 'Codex CLI trusts your home directory as a project', detail: `${path.replace(ctx.home, '~')} marks ${trustedHome.map(([p]) => p).join(', ')} as trusted. Any .codex/config.toml under it, including ones that arrive in a cloned repo, is applied without asking.`, path, agent: agent.slug })
    }
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
  const trustPath = join(ctx.home, '.gemini', 'trustedFolders.json')
  const trust = rec(readJson(trustPath))
  const trustMap = rec(trust?.['config']) ?? trust
  const home = ctx.home.replace(/[\\/]+$/, '')
  const trustedHome = Object.entries(trustMap ?? {}).filter(([folder, level]) => {
    if (level !== 'TRUST_FOLDER' && level !== 'TRUST_PARENT') return false
    const effective = (level === 'TRUST_PARENT' ? dirname(folder) : folder).replace(/[\\/]+$/, '')
    return effective === home || home.startsWith(effective + '/') || effective === '/'
  })
  const findings: Finding[] = []
  if (trustedHome.length > 0) {
    findings.push({ category: 'shell', severity: 'high', title: 'Gemini CLI trusts your home directory', detail: `${trustPath.replace(ctx.home, '~')} marks ${trustedHome.map(([f]) => f).join(', ')} as trusted, so every folder under it skips the trust prompt and loads its GEMINI.md, settings and MCP servers automatically.`, path: trustPath, agent: agent.slug })
  }
  if (yolo) {
    posture.unprompted = true
    posture.reasons.push('Gemini CLI yolo mode is enabled')
    findings.push({ category: 'shell', severity: 'high', title: 'Gemini CLI runs in YOLO mode', detail: `${path.replace(ctx.home, '~')} enables yolo. Every tool call, including shell, is auto approved.`, path, agent: agent.slug })
  } else if (autoAccept) {
    findings.push({ category: 'shell', severity: 'medium', title: 'Gemini CLI auto accepts tool calls', detail: `${path.replace(ctx.home, '~')} sets autoAccept. Read only tools run without a prompt; check whether shell is included in your version.`, path, agent: agent.slug })
  } else if (findings.length === 0) {
    findings.push({ category: 'shell', severity: 'info', title: 'Gemini CLI prompts before running commands', detail: 'No auto accept or yolo settings found.', agent: agent.slug })
  }
  return findings
}

function generic(agent: Agent, severity: Finding['severity'], detail: string): Finding {
  return { category: 'shell', severity, title: `${agent.name} can run shell commands`, detail, agent: agent.slug }
}

const OPENCLAW_MIN_SAFE = '2026.8.1'

function openclaw(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.openclaw', 'openclaw.json')
  const short = path.replace(ctx.home, '~')
  const findings: Finding[] = []
  const config = rec(readJson(path))
  const gateway = rec(config?.['gateway'])
  const auth = rec(gateway?.['auth'])
  const bind = typeof gateway?.['bind'] === 'string' ? (gateway['bind'] as string) : 'loopback'
  const authMode = typeof auth?.['mode'] === 'string' ? (auth['mode'] as string) : undefined
  const hasSecret = typeof auth?.['token'] === 'string' || typeof auth?.['password'] === 'string' || Boolean(process.env['OPENCLAW_GATEWAY_TOKEN']) || Boolean(process.env['OPENCLAW_GATEWAY_PASSWORD'])
  const exposed = bind !== 'loopback'
  const noAuth = authMode === 'none' || (exposed && !hasSecret && authMode !== 'trusted-proxy' && authMode !== 'password' && authMode !== 'token')

  if (exposed && noAuth) {
    posture.unprompted = true
    posture.reasons.push('OpenClaw gateway is reachable from the network without authentication')
    findings.push({ category: 'shell', severity: 'critical', title: 'OpenClaw gateway is on the network with no authentication', detail: `${short} sets gateway.bind to "${bind}" and no working auth. Anyone who can reach this port gets an agent that runs shell commands as you. Tens of thousands of instances were found exposed like this in 2026. Set gateway.bind to "loopback" or turn on token auth.`, path, agent: agent.slug })
  } else if (exposed) {
    findings.push({ category: 'shell', severity: 'high', title: `OpenClaw gateway listens beyond localhost (${bind})`, detail: `${short} sets gateway.bind to "${bind}". Auth is on, but the gateway has had remote code execution bugs this year, so every host on that network is one CVE away from your shell. Bind to loopback unless you need remote access.`, path, agent: agent.slug })
  } else if (authMode === 'none') {
    findings.push({ category: 'shell', severity: 'medium', title: 'OpenClaw gateway auth is disabled', detail: `${short} sets gateway.auth.mode to "none". It is only on loopback, but any local process or a browser tab that reaches localhost can drive the agent. CVE-2026-25253 was exactly this path.`, path, agent: agent.slug })
  }

  const controlUi = rec(config?.['controlUi'])
  const dangerous = ['dangerouslyAllowHostHeaderOriginFallback', 'allowExternalEmbedUrls'].filter((k) => controlUi?.[k] === true)
  if (dangerous.length > 0) {
    findings.push({ category: 'shell', severity: 'medium', title: `OpenClaw control UI has ${dangerous.join(' and ')} enabled`, detail: `${short} relaxes the origin checks that stopped the one click remote code execution bug. Turn these off unless a reverse proxy depends on them.`, path, agent: agent.slug })
  }

  if (agent.version && compareVersions(agent.version, OPENCLAW_MIN_SAFE) < 0) {
    findings.push({ category: 'shell', severity: 'high', title: `OpenClaw v${agent.version} is behind the last security release`, detail: `Two high severity fixes shipped in ${OPENCLAW_MIN_SAFE} and the project has logged more than 500 CVEs in 2026. Update before running it against anything you care about.`, agent: agent.slug })
  }

  findings.push(generic(agent, 'medium', 'OpenClaw executes skills and tools as a long running process with your user permissions. Review installed skills under ~/.openclaw.'))
  return findings
}

function cursor(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.cursor', 'cli-config.json'), join(ctx.project, '.cursor', 'cli.json')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const cfg = rec(readJson(path))
    if (!cfg) continue
    const short = path.replace(ctx.home, '~')
    const mode = cfg['approvalMode']
    if (mode === 'unrestricted') {
      posture.unprompted = true
      posture.reasons.push(`Cursor CLI approvalMode is unrestricted in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Cursor CLI runs every command unrestricted', detail: `${short} sets approvalMode to "unrestricted". Shell commands and edits run without approval.`, path, agent: agent.slug })
    } else if (mode === 'auto-review') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Cursor CLI auto reviews its own commands', detail: `${short} sets approvalMode to "auto-review". The model decides what is safe to run, you are not asked.`, path, agent: agent.slug })
    }
    const allow = strArr(rec(cfg['permissions'])?.['allow'])
    const shellAll = allow.filter((r) => /^Shell(\(\*?\))?$/.test(r.trim()))
    const risky = allow.filter((r) => /Shell\([^)]*(curl|wget|sudo|rm|chmod|ssh|scp|eval|bash|sh|npm publish|git push)/.test(r))
    if (shellAll.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Cursor CLI allow list includes ${shellAll[0]} in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Cursor CLI pre approves every shell command', detail: `${short} allow list contains "${shellAll[0]}".`, path, agent: agent.slug })
    } else if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Cursor CLI pre approves ${risky.length} risky shell pattern${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) {
    findings.push(generic(agent, 'low', 'Cursor has an integrated terminal and an auto run setting stored in its app state, which snuf cannot read. Check Cursor settings for auto run, and ~/.cursor/cli-config.json for the CLI.'))
  }
  return findings
}

function opencodePermission(value: unknown): 'allow' | 'ask' | 'deny' | undefined {
  if (value === 'allow' || value === 'ask' || value === 'deny') return value
  const star = rec(value)?.['*']
  return star === 'allow' || star === 'ask' || star === 'deny' ? star : undefined
}

function opencode(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.config', 'opencode', 'opencode.json'), join(ctx.project, 'opencode.json')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const perm = rec(rec(readJson(path))?.['permission'])
    if (!perm) continue
    const short = path.replace(ctx.home, '~')
    const all = opencodePermission(perm['*'])
    const bash = opencodePermission(perm['bash']) ?? all
    const edit = opencodePermission(perm['edit']) ?? all
    const external = opencodePermission(perm['external_directory']) ?? all
    if (bash === 'allow') {
      posture.unprompted = true
      posture.reasons.push(`OpenCode permission.bash is allow in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'OpenCode runs shell commands without asking', detail: `${short} sets permission.${perm['bash'] !== undefined ? 'bash' : '*'} to "allow". Every command the model chooses runs immediately.`, path, agent: agent.slug })
    }
    if (edit === 'allow') {
      findings.push({ category: 'shell', severity: 'medium', title: 'OpenCode edits files without asking', detail: `${short} sets permission.${perm['edit'] !== undefined ? 'edit' : '*'} to "allow".`, path, agent: agent.slug })
    }
    if (external === 'allow') {
      findings.push({ category: 'shell', severity: 'medium', title: 'OpenCode may work outside the project directory', detail: `${short} sets permission.external_directory to "allow", so reads and writes beyond the repo do not prompt.`, path, agent: agent.slug })
    }
    const bashRules = rec(perm['bash'])
    if (bashRules) {
      const risky = Object.entries(bashRules).filter(([k, v]) => k !== '*' && v === 'allow' && /curl|wget|sudo|rm|chmod|ssh|scp|eval|npm publish|git push/.test(k)).map(([k]) => k)
      if (risky.length > 0 && bash !== 'allow') {
        findings.push({ category: 'shell', severity: 'medium', title: `OpenCode pre approves ${risky.length} risky shell pattern${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
      }
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'info', 'OpenCode asks before shell commands and edits by default. Set permission rules in opencode.json to tighten further.'))
  return findings
}

interface KiroRule {
  capability: string
  match: string[]
  effect: string
}

export function parseKiroRules(text: string): KiroRule[] {
  const rules: KiroRule[] = []
  let current: KiroRule | undefined
  for (const rawLine of text.split('\n')) {
    const line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    const cap = line.match(/^-\s*capability:\s*["']?([\w]+)/)
    if (cap) {
      current = { capability: cap[1]!, match: [], effect: 'ask' }
      rules.push(current)
      continue
    }
    if (!current) continue
    const match = line.match(/^match:\s*\[(.*)\]/)
    if (match) current.match = match[1]!.split(',').map((m) => m.trim().replace(/^["']|["']$/g, '')).filter(Boolean)
    const effect = line.match(/^effect:\s*["']?(\w+)/)
    if (effect) current.effect = effect[1]!
  }
  return rules
}

function kiro(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const findings: Finding[] = []
  const yamlFiles = [join(ctx.home, '.kiro', 'settings', 'permissions.yaml'), join(ctx.project, '.kiro', 'settings', 'permissions.yaml')]
  try {
    yamlFiles.push(...fg.sync('.kiro/workspace-roots/*/permissions.yaml', { cwd: ctx.home, absolute: true, dot: true, suppressErrors: true }))
  } catch {
    // no workspace roots
  }
  for (const path of yamlFiles) {
    const text = readText(path)
    if (text === undefined) continue
    const short = path.replace(ctx.home, '~')
    const rules = parseKiroRules(text).filter((r) => r.effect === 'allow')
    const blanket = rules.filter((r) => ['shell', 'all', 'builtin'].includes(r.capability) && (r.match.length === 0 || r.match.includes('*') || r.match.includes('**')))
    if (blanket.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Kiro permissions allow ${blanket[0]!.capability} without a pattern in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Kiro CLI runs every shell command without asking', detail: `${short} has an allow rule for capability "${blanket[0]!.capability}" with no restricting pattern.`, path, agent: agent.slug })
      continue
    }
    const risky = rules.filter((r) => r.capability === 'shell').flatMap((r) => r.match).filter((m) => /curl|wget|sudo|rm|chmod|ssh|scp|eval|npm publish|git push/.test(m))
    if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Kiro CLI pre approves ${risky.length} risky shell pattern${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    }
    const fsAll = rules.filter((r) => ['fs_write', 'filesystem'].includes(r.capability) && (r.match.length === 0 || r.match.some((m) => m === '*' || m === '**' || m.startsWith('~') || m.startsWith('/'))))
    if (fsAll.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: 'Kiro CLI writes outside the project without asking', detail: `${short} allows ${fsAll[0]!.capability} on ${fsAll[0]!.match.join(', ') || 'everything'}.`, path, agent: agent.slug })
    }
  }
  let agentFiles: string[] = []
  try {
    agentFiles = fg.sync(['.kiro/agents/*.json'], { cwd: ctx.home, absolute: true, dot: true, suppressErrors: true })
  } catch {
    agentFiles = []
  }
  for (const path of agentFiles) {
    const cfg = rec(readJson(path))
    const tools = strArr(cfg?.['allowedTools'])
    if (tools.some((t) => t === '*' || t === 'shell' || t === 'execute_bash' || t === '@builtin')) {
      posture.unprompted = true
      posture.reasons.push(`Kiro agent ${String(cfg?.['name'] ?? path)} trusts shell`)
      findings.push({ category: 'shell', severity: 'high', title: `Kiro agent "${String(cfg?.['name'] ?? path.split('/').at(-1))}" trusts shell commands`, detail: `${path.replace(ctx.home, '~')} allowedTools includes ${tools.filter((t) => t === '*' || t === 'shell' || t === 'execute_bash' || t === '@builtin').join(', ')}. Commands run without confirmation whenever this agent is active.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Kiro asks before shell commands and writes by default. Rules in ~/.kiro/settings/permissions.yaml and agents under ~/.kiro/agents can change that.'))
  return findings
}

function grok(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.grok', 'config.toml'), join(ctx.project, '.grok', 'config.toml')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const text = readText(path)
    if (text === undefined) continue
    const short = path.replace(ctx.home, '~')
    const toml = parseTomlSubset(text)
    const ui = rec(toml['ui'])
    const sandbox = rec(toml['sandbox'])
    const perm = rec(toml['permission'])
    const mode = ui?.['permission_mode']
    if (mode === 'always-approve') {
      posture.unprompted = true
      posture.reasons.push(`Grok Build permission_mode is always-approve in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Grok Build approves every tool call', detail: `${short} sets ui.permission_mode = "always-approve". Shell commands, edits and MCP tools run without a prompt.`, path, agent: agent.slug })
    } else if (mode === 'auto') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Grok Build auto approves tool calls', detail: `${short} sets ui.permission_mode = "auto". The model decides what needs your approval.`, path, agent: agent.slug })
    }
    if (sandbox?.['auto_allow_bash'] === true) {
      posture.unprompted = true
      posture.reasons.push(`Grok Build sandbox.auto_allow_bash is on in ${short}`)
      findings.push({ category: 'shell', severity: sandbox['profile'] && sandbox['profile'] !== 'off' ? 'medium' : 'high', title: 'Grok Build runs shell commands without asking', detail: `${short} sets sandbox.auto_allow_bash = true${sandbox['profile'] && sandbox['profile'] !== 'off' ? ` inside the "${String(sandbox['profile'])}" sandbox profile` : ' and the sandbox profile is off, so nothing contains those commands'}.`, path, agent: agent.slug })
    }
    const allow = strArr(perm?.['allow'])
    const bashAll = allow.filter((r) => /^Bash(\(\*?\))?$/.test(r.trim()))
    if (bashAll.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Grok Build permission.allow includes ${bashAll[0]} in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Grok Build pre approves every shell command', detail: `${short} permission.allow contains "${bashAll[0]}".`, path, agent: agent.slug })
    }
    if (ui?.['default_selected_permission'] === 'always_allow_all_sessions' && findings.length === 0) {
      findings.push({ category: 'shell', severity: 'low', title: 'Grok Build defaults every approval prompt to "always allow"', detail: `${short} keeps ui.default_selected_permission = "always_allow_all_sessions" (the default). One Enter on a prompt approves that tool forever. Set it to allow_once.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Grok Build prompts before tool calls by default and its sandbox profile is off unless set in ~/.grok/config.toml. Note the default prompt selection is "always allow for all sessions".'))
  return findings
}

function kimi(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.kimi-code', 'config.toml'), join(ctx.project, '.kimi-code', 'local.toml')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const text = readText(path)
    if (text === undefined) continue
    const short = path.replace(ctx.home, '~')
    const toml = parseTomlSubset(text)
    const perm = rec(toml['permission'])
    if (perm?.['default_permission_mode'] === 'yolo' || toml['default_permission_mode'] === 'yolo') {
      posture.unprompted = true
      posture.reasons.push(`Kimi Code default_permission_mode is yolo in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Kimi Code runs in yolo mode', detail: `${short} sets default_permission_mode = "yolo". Every tool call, including shell, is auto approved.`, path, agent: agent.slug })
    }
    if (perm?.['dangerous_command_guard'] === false) {
      findings.push({ category: 'shell', severity: 'medium', title: 'Kimi Code dangerous command guard is off', detail: `${short} sets permission.dangerous_command_guard = false. rm -rf style commands no longer get a confirmation.`, path, agent: agent.slug })
    }
    const allowAll = text.split('[[permission.rules]]').slice(1).filter((block) => /decision\s*=\s*"allow"/.test(block) && /pattern\s*=\s*"(Bash|Shell|\*)(\(\*?\))?"/.test(block))
    if (allowAll.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Kimi Code permission rule allows Bash in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Kimi Code pre approves every shell command', detail: `${short} has a permission rule with decision = "allow" for Bash.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'info', 'Kimi Code prompts before tool calls (manual mode) and guards dangerous commands by default.'))
  return findings
}

function hermes(agent: Agent, ctx: ScanContext): Finding[] {
  const path = join(ctx.home, '.hermes', 'config.yaml')
  const text = readText(path)
  const findings: Finding[] = []
  if (text !== undefined) {
    if (/dangerous_command_approval:\s*false/.test(text)) {
      findings.push({ category: 'shell', severity: 'medium', title: 'Hermes Agent dangerous command approval is off', detail: '~/.hermes/config.yaml sets agent.dangerous_command_approval: false. Commands like rm -rf run without a prompt.', path, agent: agent.slug })
    }
    const backend = text.match(/^\s*backend:\s*["']?(\w+)/m)?.[1]
    if (backend && backend !== 'local') {
      findings.push({ category: 'shell', severity: 'info', title: `Hermes Agent runs commands in a ${backend} sandbox`, detail: `terminal.backend is "${backend}", so shell commands do not run directly on this machine.`, path, agent: agent.slug })
      return findings
    }
  }
  findings.push(generic(agent, 'medium', 'Hermes Agent runs as a long lived process with shell, browser and messaging tools on this machine (terminal.backend local). Secrets live in ~/.hermes/.env, which every tool it runs can read.'))
  return findings
}

function factory(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [
    join(ctx.home, '.factory', 'settings.json'),
    join(ctx.home, '.factory', 'settings.local.json'),
    join(ctx.project, '.factory', 'settings.local.json'),
  ].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const settings = rec(readJson(path))
    if (!settings) continue
    const short = path.replace(ctx.home, '~')
    const level = rec(settings['sessionDefaultSettings'])?.['autonomyLevel']
    if (level === 'high') {
      posture.unprompted = true
      posture.reasons.push(`Factory Droid autonomyLevel is high in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Factory Droid starts every session at full autonomy', detail: `${short} sets sessionDefaultSettings.autonomyLevel to "high". Commands outside the blocklist run without confirmation.`, path, agent: agent.slug })
    } else if (level === 'medium') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Factory Droid auto runs most commands', detail: `${short} sets autonomyLevel to "medium". Only commands on the denylist stop for confirmation.`, path, agent: agent.slug })
    }
    const allow = strArr(settings['commandAllowlist'])
    const risky = allow.filter((r) => /curl|wget|sudo|rm |chmod|ssh|scp|eval|bash -c|sh -c|npm publish|git push|\*/.test(r))
    if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Factory Droid pre approves ${risky.length} risky command pattern${risky.length > 1 ? 's' : ''}`, detail: `${short} commandAllowlist: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'info', 'Factory Droid starts with autonomy off and asks before commands.'))
  return findings
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
        findings.push(...cursor(agent, ctx, posture))
        break
      case 'opencode':
        findings.push(...opencode(agent, ctx, posture))
        break
      case 'kiro':
        findings.push(...kiro(agent, ctx, posture))
        break
      case 'windsurf':
      case 'trae':
      case 'zed':
      case 'antigravity':
        findings.push(generic(agent, 'low', `${agent.name} has an integrated terminal and an auto run setting stored in its app state, which snuf cannot read. Check the agent settings for auto run or turbo mode.`))
        break
      case 'aider':
        findings.push(generic(agent, 'low', 'Aider runs lint and test commands automatically when configured with auto-lint or auto-test.'))
        break
      case 'openclaw':
        findings.push(...openclaw(agent, ctx, posture))
        break
      case 'factory':
        findings.push(...factory(agent, ctx, posture))
        break
      case 'hermes':
        findings.push(...hermes(agent, ctx))
        break
      case 'kimi-code':
        findings.push(...kimi(agent, ctx, posture))
        break
      case 'grok':
        findings.push(...grok(agent, ctx, posture))
        break
      case 'claude-desktop':
        break
      default:
        findings.push(generic(agent, 'low', `${agent.name} is installed. Verify its command approval settings.`))
    }
  }

  return { findings, posture }
}
