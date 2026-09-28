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

  findings.push(...claudePlugins(agent, ctx, promptsIntact))

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

function claudePlugins(agent: Agent, ctx: ScanContext, promptsIntact: boolean): Finding[] {
  const findings: Finding[] = []
  const marketsPath = join(ctx.home, '.claude', 'plugins', 'known_marketplaces.json')
  const markets = rec(readJson(marketsPath))
  const thirdParty = Object.entries(markets ?? {}).filter(([name]) => name !== 'claude-plugins-official')
  if (thirdParty.length > 0) {
    const installed = rec(rec(readJson(join(ctx.home, '.claude', 'plugins', 'installed_plugins.json')))?.['plugins'])
    const fromThirdParty = Object.keys(installed ?? {}).filter((k) => thirdParty.some(([name]) => k.endsWith(`@${name}`)))
    findings.push({
      category: 'shell',
      severity: fromThirdParty.length > 0 ? 'medium' : 'low',
      title: `${thirdParty.length} third party Claude Code plugin marketplace${thirdParty.length > 1 ? 's' : ''}${fromThirdParty.length > 0 ? `, ${fromThirdParty.length} plugin${fromThirdParty.length > 1 ? 's' : ''} installed` : ''}`,
      detail: `${marketsPath.replace(ctx.home, '~')}: ${thirdParty.map(([name, v]) => `${name} (${String(rec(rec(v)?.['source'])?.['repo'] ?? rec(rec(v)?.['source'])?.['source'] ?? 'unknown source')})`).join(', ')}.${fromThirdParty.length > 0 ? ` Installed from them: ${fromThirdParty.slice(0, 4).join(', ')}.` : ''} Plugins run skills, hooks and MCP servers with full trust. Plugin4Shell (Sept 2026) showed the pinned SHA was not verified on checkout, so whoever controls the marketplace repo controls what runs.`,
      path: marketsPath,
      agent: agent.slug,
    })
  }
  let channels: string[] = []
  try {
    channels = fg.sync('.claude/channels/*/', { cwd: ctx.home, dot: true, onlyDirectories: true, suppressErrors: true }).map((d) => d.split('/').filter(Boolean).at(-1) ?? d)
  } catch {
    channels = []
  }
  if (channels.length > 0) {
    findings.push({
      category: 'shell',
      severity: promptsIntact ? 'medium' : 'high',
      title: `Claude Code can be driven from ${channels.join(', ')}`,
      detail: `~/.claude/channels has ${channels.join(' and ')} configured. Anyone on the allowlist for that bot can send prompts to a running session on this machine.${promptsIntact ? ' Permission prompts still apply, so the sender cannot run commands without you approving.' : ' With prompts off, a message from an allowlisted sender is a shell on this machine.'}`,
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

interface CodexRule {
  pattern: string[]
  decision: string
}

export function parseCodexRules(text: string): CodexRule[] {
  const rules: CodexRule[] = []
  for (const m of text.matchAll(/prefix_rule\s*\(([\s\S]*?)\)\s*(?=\n|$)/g)) {
    const body = m[1]!
    const pattern = body.match(/pattern\s*=\s*\[([^\]]*)\]/)?.[1] ?? ''
    const decision = body.match(/decision\s*=\s*["'](\w+)["']/)?.[1] ?? 'prompt'
    rules.push({ pattern: pattern.split(',').map((x) => x.trim().replace(/^["']|["']$/g, '')).filter(Boolean), decision })
  }
  return rules
}

const INTERPRETERS = new Set(['python', 'python3', 'node', 'npx', 'bunx', 'uvx', 'docker', 'perl', 'ruby', 'deno', 'bun'])
const SHELLS = new Set(['bash', 'sh', 'zsh', 'fish', 'dash', 'ksh'])

function isBareShell(p: string[]): boolean {
  const base = p[0]?.split('/').at(-1) ?? ''
  if (!SHELLS.has(base)) return p.length === 1 && p[0] === '*'
  return p.length === 1 || (p.length === 2 && /^-l?c$/.test(p[1] ?? ''))
}

export function riskyPrefix(p: string[]): boolean {
  const base = p[0]?.split('/').at(-1) ?? ''
  const second = p[1] ?? ''
  if (['sudo', 'doas', 'eval', 'nc', 'ncat', 'socat'].includes(base)) return true
  if (['curl', 'wget'].includes(base)) return !p.some((x) => /^https?:\/\//.test(x))
  if (['rm', 'rmdir', 'chmod', 'chown', 'ssh', 'scp', 'rsync', 'dd', 'mkfs'].includes(base)) return p.length === 1 || (p.length === 2 && second.startsWith('-'))
  if (INTERPRETERS.has(base)) return p.length === 1 || (p.length === 2 && /^-(c|e|p)$/.test(second))
  if (base === 'git' && (second === 'push' || second === 'clean' || second === 'reset')) return p.length === 2
  if (base === 'npm' && second === 'publish') return true
  if (base === 'gh' && ['auth', 'secret', 'release'].includes(second)) return p.length <= 2
  return false
}

function codexRules(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const findings: Finding[] = []
  const dirs = [join(ctx.home, '.codex', 'rules'), join(ctx.project, '.codex', 'rules')]
  for (const dir of dirs) {
    let files: string[] = []
    try {
      files = fg.sync('*.rules', { cwd: dir, absolute: true, suppressErrors: true })
    } catch {
      continue
    }
    for (const path of files) {
      const text = readText(path)
      if (text === undefined) continue
      const short = path.replace(ctx.home, '~')
      const allows = parseCodexRules(text).filter((r) => r.decision === 'allow')
      const shells = allows.filter((r) => isBareShell(r.pattern))
      if (shells.length > 0) {
        posture.unprompted = true
        posture.reasons.push(`Codex execution policy allows ${shells[0]!.pattern[0]} in ${short}`)
        findings.push({ category: 'shell', severity: 'high', title: 'Codex CLI execution policy allows a bare shell', detail: `${short} allows "${shells[0]!.pattern.join(' ')}" with no further prefix. Anything after it runs outside the sandbox without a prompt.`, path, agent: agent.slug })
        continue
      }
      const risky = allows.filter((r) => riskyPrefix(r.pattern))
      if (risky.length > 0) {
        findings.push({ category: 'shell', severity: 'medium', title: `Codex CLI execution policy pre approves ${risky.length} risky command prefix${risky.length > 1 ? 'es' : ''}`, detail: `${short} has ${allows.length} allow rules. Open ended ones: ${risky.slice(0, 6).map((r) => r.pattern.join(' ')).join(', ')}${risky.length > 6 ? ` and ${risky.length - 6} more` : ''}. These run outside the sandbox without a prompt, and a prefix like "curl -s" matches any URL.`, path, agent: agent.slug })
      } else if (allows.length > 0) {
        findings.push({ category: 'shell', severity: 'info', title: `Codex CLI execution policy pre approves ${allows.length} command prefix${allows.length > 1 ? 'es' : ''}`, detail: `${short}: ${allows.slice(0, 8).map((r) => r.pattern.join(' ')).join(', ')}${allows.length > 8 ? ' and more' : ''}.`, path, agent: agent.slug })
      }
    }
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
  findings.push(...codexRules(agent, ctx, posture))
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
  findings.push({ category: 'shell', severity: 'info', title: 'Gemini CLI stopped serving non enterprise users on 2026-06-18', detail: 'Google replaced it with Antigravity CLI (~/.gemini/antigravity-cli). If this install still works you are on a Gemini Code Assist licence; otherwise the config here is dead weight and any MCP credentials in it should be moved or deleted.', agent: agent.slug })
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
  for (const path of [join(ctx.home, '.cursor', 'hooks.json'), join(ctx.project, '.cursor', 'hooks.json')]) {
    const hooks = rec(rec(readJson(path))?.['hooks'])
    if (!hooks) continue
    let count = 0
    for (const list of Object.values(hooks)) if (Array.isArray(list)) count += list.filter((h) => typeof rec(h)?.['command'] === 'string').length
    if (count === 0) continue
    const projectScoped = path.startsWith(ctx.project)
    findings.push({ category: 'shell', severity: projectScoped ? 'medium' : 'low', title: `${count} Cursor hook${count > 1 ? 's' : ''} run${count > 1 ? '' : 's'} shell commands automatically`, detail: `${path.replace(ctx.home, '~')} defines hooks on ${Object.keys(hooks).join(', ')}. They execute without a prompt.${projectScoped ? ' Project scoped hooks run for anyone who opens the repo in Cursor.' : ''}`, path, agent: agent.slug })
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

function isHomeOrAncestor(dir: string, home: string): boolean {
  const d = dir.replace(/^~/, home).replace(/[\\/]+$/, '')
  const h = home.replace(/[\\/]+$/, '')
  return d === h || h.startsWith(d + '/') || d === '/'
}

function amp(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.config', 'amp', 'settings.json')
  const settings = rec(readJson(path))
  const findings: Finding[] = []
  if (settings) {
    const short = path.replace(ctx.home, '~')
    if (settings['amp.dangerouslyAllowAll'] === true) {
      posture.unprompted = true
      posture.reasons.push('Amp dangerouslyAllowAll is on')
      findings.push({ category: 'shell', severity: 'high', title: 'Amp runs every command without asking', detail: `${short} sets amp.dangerouslyAllowAll to true. The name says it.`, path, agent: agent.slug })
    }
    const perms = Array.isArray(settings['amp.permissions']) ? (settings['amp.permissions'] as unknown[]) : []
    const bashAll = perms.filter((p) => {
      const r = rec(p)
      const cmds = strArr(rec(r?.['matches'])?.['cmd'])
      return r?.['tool'] === 'Bash' && r['action'] === 'allow' && (cmds.length === 0 || cmds.includes('*'))
    })
    if (bashAll.length > 0 && settings['amp.dangerouslyAllowAll'] !== true) {
      posture.unprompted = true
      posture.reasons.push('Amp permissions allow every Bash command')
      findings.push({ category: 'shell', severity: 'high', title: 'Amp pre approves every shell command', detail: `${short} has an amp.permissions rule that allows Bash with no command pattern.`, path, agent: agent.slug })
    }
    const allowlist = strArr(settings['amp.commands.allowlist'])
    const risky = allowlist.filter((c) => /curl|wget|sudo|rm |chmod|ssh|scp|eval|npm publish|git push|^\*$/.test(c))
    if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Amp pre approves ${risky.length} risky command${risky.length > 1 ? 's' : ''}`, detail: `${short} amp.commands.allowlist: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Amp asks before commands that are not on amp.commands.allowlist. Review that list in ~/.config/amp/settings.json.'))
  return findings
}

function goose(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.config', 'goose', 'config.yaml')
  const text = readText(path)
  const short = path.replace(ctx.home, '~')
  const mode = text?.match(/^\s*GOOSE_MODE:\s*["']?([\w]+)/m)?.[1] ?? process.env['GOOSE_MODE']
  if (mode === 'auto' || (text !== undefined && mode === undefined)) {
    posture.unprompted = true
    posture.reasons.push(mode === 'auto' ? 'Goose GOOSE_MODE is auto' : 'Goose GOOSE_MODE is unset, which defaults to auto')
    return [{ category: 'shell', severity: mode === 'auto' ? 'high' : 'medium', title: mode === 'auto' ? 'Goose auto approves every tool call' : 'Goose has no GOOSE_MODE set, so it auto approves', detail: `${short} ${mode === 'auto' ? 'sets GOOSE_MODE: auto' : 'does not set GOOSE_MODE, and the built in default is auto (goose issue #12448)'}. Shell commands and file writes run without a prompt. Set GOOSE_MODE: smart_approve or approve.`, path, agent: agent.slug }]
  }
  if (mode === 'smart_approve') {
    return [{ category: 'shell', severity: 'low', title: 'Goose lets a model decide which tool calls need approval', detail: `${short} sets GOOSE_MODE: smart_approve. Read only looking calls are auto approved based on tool annotations and an LLM judge.`, path, agent: agent.slug }]
  }
  if (mode === 'approve' || mode === 'chat') {
    return [{ category: 'shell', severity: 'info', title: `Goose runs in ${mode} mode`, detail: `${short} sets GOOSE_MODE: ${mode}.`, path, agent: agent.slug }]
  }
  return [generic(agent, 'low', 'Goose config not found. Its default permission mode is auto, which approves every tool call.')]
}

function copilot(agent: Agent, ctx: ScanContext): Finding[] {
  const path = join(ctx.home, '.copilot', 'config.json')
  const cfg = rec(readJson(path))
  const trusted = strArr(cfg?.['trusted_folders']).filter((d) => isHomeOrAncestor(d, ctx.home))
  if (trusted.length > 0) {
    return [{ category: 'shell', severity: 'high', title: 'Copilot CLI trusts your home directory', detail: `${path.replace(ctx.home, '~')} lists ${trusted.join(', ')} under trusted_folders. Every session under it can read, write and execute without the folder trust prompt.`, path, agent: agent.slug }]
  }
  return [generic(agent, 'low', 'Copilot CLI asks per tool unless started with --allow-tool or --allow-all-tools. Trusted folders live in ~/.copilot/config.json.')]
}

function antigravity(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.gemini', 'config', 'config.json')
  const user = rec(rec(readJson(path))?.['userSettings'])
  const findings: Finding[] = []
  if (user) {
    const short = path.replace(ctx.home, '~')
    const policy = user['autoExecutionPolicy']
    const sandboxed = user['enableTerminalSandbox'] === true
    if (policy === 'Always Proceed') {
      posture.unprompted = true
      posture.reasons.push('Antigravity autoExecutionPolicy is Always Proceed')
      findings.push({ category: 'shell', severity: sandboxed ? 'medium' : 'high', title: 'Antigravity runs terminal commands without review', detail: `${short} sets autoExecutionPolicy to "Always Proceed". Everything outside the denylist runs immediately${sandboxed ? ', inside the terminal sandbox' : ' and enableTerminalSandbox is off'}.`, path, agent: agent.slug })
    }
    const allow = strArr(rec(user['globalPermissionGrants'])?.['allow'])
    const commandAll = allow.filter((r) => /^command(:\*|\(\*\))?$/.test(r.trim()))
    if (commandAll.length > 0 && policy !== 'Always Proceed') {
      posture.unprompted = true
      posture.reasons.push('Antigravity globalPermissionGrants allow every command')
      findings.push({ category: 'shell', severity: 'high', title: 'Antigravity pre approves every command', detail: `${short} globalPermissionGrants.allow contains "${commandAll[0]}".`, path, agent: agent.slug })
    }
    if (user['nonWorkspaceFileAccessPolicy'] === 'Always Proceed' || user['nonWorkspaceFileAccessPolicy'] === true) {
      findings.push({ category: 'shell', severity: 'medium', title: 'Antigravity reads and writes outside the workspace without asking', detail: `${short} sets nonWorkspaceFileAccessPolicy to allow. Files anywhere in your home directory are fair game.`, path, agent: agent.slug })
    }
    if (findings.length === 0 && sandboxed) {
      findings.push({ category: 'shell', severity: 'info', title: 'Antigravity terminal sandbox is on', detail: `${short} sets enableTerminalSandbox.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Antigravity asks before terminal commands by default (Request Review). Its policy lives in ~/.gemini/config/config.json under userSettings.'))
  return findings
}

function antigravityCli(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.gemini', 'antigravity-cli', 'settings.json')
  const settings = rec(readJson(path))
  const findings: Finding[] = []
  if (settings) {
    const short = path.replace(ctx.home, '~')
    const allow = strArr(rec(settings['permissions'])?.['allow'])
    const commandAll = allow.filter((r) => /^command(\(\*?\))?$/.test(r.trim()))
    const risky = allow.filter((r) => /command\([^)]*(curl|wget|sudo|rm|chmod|ssh|scp|eval|bash|sh|npm publish|git push)/.test(r))
    if (commandAll.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Antigravity CLI allows every command in ${short}`)
      findings.push({ category: 'shell', severity: settings['enableTerminalSandbox'] === true ? 'medium' : 'high', title: 'Antigravity CLI pre approves every command', detail: `${short} permissions.allow contains "${commandAll[0]}"${settings['enableTerminalSandbox'] === true ? ' (terminal sandbox is on)' : ' and enableTerminalSandbox is off'}.`, path, agent: agent.slug })
    } else if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Antigravity CLI pre approves ${risky.length} risky command pattern${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    } else if (settings['enableTerminalSandbox'] === true) {
      findings.push({ category: 'shell', severity: 'info', title: 'Antigravity CLI terminal sandbox is on', detail: `${short} sets enableTerminalSandbox.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Antigravity CLI asks before commands by default and its terminal sandbox is off unless enableTerminalSandbox is set in ~/.gemini/antigravity-cli/settings.json.'))
  return findings
}

function yamlBool(text: string, key: string): boolean | undefined {
  const m = text.match(new RegExp(`^\\s*${key}:\\s*(true|false)\\b`, 'm'))
  return m ? m[1] === 'true' : undefined
}

function aider(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.aider.conf.yml'), join(ctx.project, '.aider.conf.yml')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const text = readText(path)
    if (text === undefined) continue
    const short = path.replace(ctx.home, '~')
    if (yamlBool(text, 'yes-always') === true) {
      posture.unprompted = true
      posture.reasons.push(`Aider yes-always is set in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Aider answers yes to every prompt', detail: `${short} sets yes-always: true. Shell commands Aider proposes, file creation and git operations all proceed without confirmation.${path.startsWith(ctx.project) ? ' This file is project scoped, so it applies to anyone who clones the repo.' : ''}`, path, agent: agent.slug })
    }
    const keyLine = text.match(/^\s*(openai-api-key|anthropic-api-key|api-key|openrouter-api-key|deepseek-api-key|gemini-api-key)\s*:\s*["']?([^\s"'#]{8,})/im)
    if (keyLine) {
      findings.push({ category: 'secret', severity: 'critical', title: `${keyLine[1]!} stored in plaintext in Aider config`, detail: `${short} holds an API key inline. Move it to an environment variable or ~/.aider/.env.`, path, agent: agent.slug })
    }
    const autoRun = ['auto-test', 'auto-lint'].filter((k) => yamlBool(text, k) === true)
    if (autoRun.length > 0) {
      findings.push({ category: 'shell', severity: 'low', title: `Aider runs ${autoRun.join(' and ')} commands after every edit`, detail: `${short} enables ${autoRun.join(', ')}. The configured test-cmd and lint-cmd run without a prompt, and Aider commits with --no-verify by default, so pre commit hooks are skipped.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Aider asks before running commands unless yes-always is set. Note it commits with --no-verify by default, so pre commit secret scanners do not run.'))
  return findings
}

function zed(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.config', 'zed', 'settings.json'), join(ctx.project, '.zed', 'settings.json')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const agentCfg = rec(rec(readJson(path))?.['agent'])
    if (!agentCfg) continue
    const short = path.replace(ctx.home, '~')
    const legacy = agentCfg['always_allow_tool_actions'] === true
    const modern = rec(agentCfg['tool_permissions'])?.['default'] === 'allow'
    if (legacy || modern) {
      posture.unprompted = true
      posture.reasons.push(`Zed agent auto approves tools in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Zed agent runs every tool without confirmation', detail: `${short} sets ${legacy ? 'agent.always_allow_tool_actions: true' : 'agent.tool_permissions.default: "allow"'}. Terminal commands, edits and MCP tools all skip the prompt. Zed's own "always allow" button writes this for all tools, not just the one you clicked.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Zed asks per tool action unless agent.always_allow_tool_actions or agent.tool_permissions.default is set to allow in settings.json.'))
  return findings
}

function yamlList(text: string, key: string): string[] {
  const block = text.match(new RegExp(`^${key}:\\s*\\n((?:[ \\t]+-.*\\n?)+)`, 'm'))?.[1]
  if (block) return block.split('\n').map((l) => l.replace(/^\s*-\s*/, '').trim().replace(/^["']|["']$/g, '')).filter(Boolean)
  const inline = text.match(new RegExp(`^${key}:\\s*\\[(.*)\\]`, 'm'))?.[1]
  return inline ? inline.split(',').map((x) => x.trim().replace(/^["']|["']$/g, '')).filter(Boolean) : []
}

function continueCli(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const path = join(ctx.home, '.continue', 'permissions.yaml')
  const text = readText(path)
  const findings: Finding[] = []
  if (text !== undefined) {
    const short = path.replace(ctx.home, '~')
    const allow = yamlList(text, 'allow')
    const bashAll = allow.filter((r) => /^Bash(\(\*?\))?$/.test(r))
    const risky = allow.filter((r) => /^Bash\([^)]*(curl|wget|sudo|rm|chmod|ssh|scp|eval|npm publish|git push)/.test(r))
    if (bashAll.length > 0) {
      posture.unprompted = true
      posture.reasons.push(`Continue permissions allow ${bashAll[0]}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Continue CLI pre approves every shell command', detail: `${short} allow list contains "${bashAll[0]}". The TUI writes entries here when you pick "always allow".`, path, agent: agent.slug })
    } else if (risky.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: `Continue CLI pre approves ${risky.length} risky shell pattern${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path, agent: agent.slug })
    }
    if (allow.some((r) => /^Write(\(\*?\))?$/.test(r)) && findings.length === 0) {
      findings.push({ category: 'shell', severity: 'low', title: 'Continue CLI writes files without asking', detail: `${short} allows Write for every path.`, path, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Continue asks per tool unless started with --auto. Persistent approvals accumulate in ~/.continue/permissions.yaml as you click "always allow".'))
  return findings
}

function vibe(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.vibe', 'config.toml'), join(ctx.project, '.vibe', 'config.toml')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const text = readText(path)
    if (text === undefined) continue
    const short = path.replace(ctx.home, '~')
    const toml = parseTomlSubset(text)
    const agentName = toml['agent'] ?? toml['default_agent']
    if (agentName === 'auto-approve') {
      posture.unprompted = true
      posture.reasons.push(`Vibe default agent is auto-approve in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Mistral Vibe auto approves every tool call', detail: `${short} sets the default agent to "auto-approve". Mistral's own docs say to reserve this for disposable environments without SSH keys or cloud credentials.`, path, agent: agent.slug })
    } else if (agentName === 'accept-edits') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Mistral Vibe auto approves file edits', detail: `${short} sets the default agent to "accept-edits".`, path, agent: agent.slug })
    }
  }
  const trustPath = join(ctx.home, '.vibe', 'trusted_folders.toml')
  const trustText = readText(trustPath)
  if (trustText !== undefined) {
    const home = ctx.home.replace(/[\\/]+$/, '')
    const trusted = [...trustText.matchAll(/["']([^"']+)["']/g)].map((m) => m[1]!).filter((f) => isHomeOrAncestor(f, home))
    if (trusted.length > 0) {
      findings.push({ category: 'shell', severity: 'high', title: 'Mistral Vibe trusts your home directory', detail: `${trustPath.replace(ctx.home, '~')} lists ${trusted.join(', ')}. Every folder under it skips the trust prompt.`, path: trustPath, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Mistral Vibe uses the "ask" agent by default. --yolo or agent = "auto-approve" in ~/.vibe/config.toml removes every prompt.'))
  return findings
}

function qwen(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const files = [join(ctx.home, '.qwen', 'settings.json'), join(ctx.project, '.qwen', 'settings.json')].filter((p) => existsSync(p))
  const findings: Finding[] = []
  for (const path of files) {
    const settings = rec(readJson(path))
    if (!settings) continue
    const short = path.replace(ctx.home, '~')
    const mode = rec(settings['tools'])?.['approvalMode'] ?? settings['approvalMode']
    if (mode === 'yolo') {
      posture.unprompted = true
      posture.reasons.push(`Qwen Code approvalMode is yolo in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Qwen Code runs in YOLO mode', detail: `${short} sets tools.approvalMode to "yolo". Every tool call, including shell, is auto approved.`, path, agent: agent.slug })
    } else if (mode === 'auto') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Qwen Code lets a classifier approve tool calls', detail: `${short} sets tools.approvalMode to "auto". An LLM decides what is safe to run.`, path, agent: agent.slug })
    } else if (mode === 'auto-edit') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Qwen Code auto approves file edits', detail: `${short} sets tools.approvalMode to "auto-edit".`, path, agent: agent.slug })
    }
  }
  const trustPath = join(ctx.home, '.qwen', 'trustedFolders.json')
  const trust = rec(readJson(trustPath))
  const trustMap = rec(trust?.['config']) ?? trust
  const home = ctx.home.replace(/[\\/]+$/, '')
  const trustedHome = Object.entries(trustMap ?? {}).filter(([folder, level]) => {
    if (level !== 'TRUST_FOLDER' && level !== 'TRUST_PARENT') return false
    const effective = (level === 'TRUST_PARENT' ? dirname(folder) : folder).replace(/[\\/]+$/, '')
    return effective === home || home.startsWith(effective + '/') || effective === '/'
  })
  if (trustedHome.length > 0) {
    findings.push({ category: 'shell', severity: 'high', title: 'Qwen Code trusts your home directory', detail: `${trustPath.replace(ctx.home, '~')} marks ${trustedHome.map(([f]) => f).join(', ')} as trusted, so every folder under it skips the trust prompt and yolo mode is not overridden there.`, path: trustPath, agent: agent.slug })
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Qwen Code asks before edits and shell commands (approvalMode default). Note it had no GitSpawn fix at publication.'))
  return findings
}

function junieRules(section: unknown): Array<{ prefix?: string; pattern?: string; action: string }> {
  const list = rec(section)?.['rules']
  if (!Array.isArray(list)) return []
  return list.map((r) => rec(r)).filter((r): r is Record<string, unknown> => r !== undefined).map((r) => ({
    prefix: typeof r['prefix'] === 'string' ? (r['prefix'] as string) : undefined,
    pattern: typeof r['pattern'] === 'string' ? (r['pattern'] as string) : undefined,
    action: typeof r['action'] === 'string' ? (r['action'] as string) : 'ask',
  }))
}

function junie(agent: Agent, ctx: ScanContext, posture: ShellPosture): Finding[] {
  const findings: Finding[] = []
  for (const path of [join(ctx.home, '.junie', 'config.json'), join(ctx.project, '.junie', 'config.json')]) {
    const cfg = rec(readJson(path))
    if (!cfg) continue
    const short = path.replace(ctx.home, '~')
    const brave = cfg['brave']
    if (brave === true || brave === 'on') {
      posture.unprompted = true
      posture.reasons.push(`Junie brave mode is on in ${short}`)
      findings.push({ category: 'shell', severity: 'high', title: 'Junie runs in brave mode', detail: `${short} sets brave to ${JSON.stringify(brave)}. Terminal commands, MCP tools and edits outside the project run without asking.`, path, agent: agent.slug })
    } else if (brave === 'auto') {
      findings.push({ category: 'shell', severity: 'medium', title: 'Junie auto approves commands it considers safe', detail: `${short} sets brave to "auto".`, path, agent: agent.slug })
    }
    const byok = rec(cfg['byok'])
    const keyed = Object.entries(byok ?? {}).filter(([, v]) => typeof v === 'string' && (v as string).length >= 16 && !(v as string).startsWith('$'))
    if (keyed.length > 0) {
      findings.push({ category: 'secret', severity: 'critical', title: `${keyed.length} API key${keyed.length > 1 ? 's' : ''} stored in plaintext in Junie config`, detail: `${short} byok holds ${keyed.map(([k]) => k).join(', ')} inline. Reference an environment variable instead.`, path, agent: agent.slug })
    }
    if (Array.isArray(cfg['hooks']) && (cfg['hooks'] as unknown[]).length > 0) {
      findings.push({ category: 'shell', severity: path.startsWith(ctx.project) ? 'medium' : 'low', title: 'Junie hooks run shell commands automatically', detail: `${short} defines ${(cfg['hooks'] as unknown[]).length} session hook${(cfg['hooks'] as unknown[]).length > 1 ? 's' : ''}.${path.startsWith(ctx.project) ? ' Project scoped, so they run for anyone who clones the repo.' : ''}`, path, agent: agent.slug })
    }
  }
  const allowPath = join(ctx.home, '.junie', 'allowlist.json')
  const allowlist = rec(readJson(allowPath))
  if (allowlist) {
    const short = allowPath.replace(ctx.home, '~')
    const rules = rec(allowlist['rules'])
    if (allowlist['defaultBehavior'] === 'allow') {
      posture.unprompted = true
      posture.reasons.push('Junie allowlist defaultBehavior is allow')
      findings.push({ category: 'shell', severity: 'high', title: 'Junie allows every action by default', detail: `${short} sets defaultBehavior to "allow". The allowlist becomes a denylist with nothing in it.`, path: allowPath, agent: agent.slug })
    }
    const exec = junieRules(rules?.['executables']).filter((r) => r.action === 'allow')
    const blanket = exec.filter((r) => r.prefix === '' || r.pattern === '*' || r.pattern === '**' || /^(bash|sh|zsh)$/.test(r.prefix ?? ''))
    if (blanket.length > 0 && allowlist['defaultBehavior'] !== 'allow') {
      posture.unprompted = true
      posture.reasons.push('Junie allowlist allows every executable')
      findings.push({ category: 'shell', severity: 'high', title: 'Junie pre approves every terminal command', detail: `${short} has an executables rule with ${blanket[0]!.prefix !== undefined ? `prefix "${blanket[0]!.prefix}"` : `pattern "${blanket[0]!.pattern}"`}.`, path: allowPath, agent: agent.slug })
    } else {
      const risky = exec.map((r) => r.prefix ?? r.pattern ?? '').filter((p) => /^(curl|wget|sudo|rm|chmod|ssh|scp|eval|npm publish|git push)/.test(p))
      if (risky.length > 0) findings.push({ category: 'shell', severity: 'medium', title: `Junie pre approves ${risky.length} risky command${risky.length > 1 ? 's' : ''}`, detail: `${short}: ${risky.slice(0, 6).join(', ')}`, path: allowPath, agent: agent.slug })
    }
    if (junieRules(rules?.['readSecretFile']).some((r) => r.action === 'allow')) {
      findings.push({ category: 'shell', severity: 'high', title: 'Junie may read secret files without asking', detail: `${short} has an allow rule under readSecretFile. Junie's own classifier flagged those paths as likely credentials.`, path: allowPath, agent: agent.slug })
    }
    const outside = junieRules(rules?.['readOutsideProject']).filter((r) => r.action === 'allow' && /^(\/|~|\$HOME)?\*\*?$|^\/\*\*$|^~\/\*\*$/.test(r.pattern ?? r.prefix ?? ''))
    if (outside.length > 0) {
      findings.push({ category: 'shell', severity: 'medium', title: 'Junie reads anywhere outside the project without asking', detail: `${short} allows readOutsideProject for ${outside[0]!.pattern ?? outside[0]!.prefix}.`, path: allowPath, agent: agent.slug })
    }
  }
  if (findings.length === 0) findings.push(generic(agent, 'low', 'Junie asks before terminal commands, MCP tools and reads outside the project unless brave mode is on. Approvals you accept persist in ~/.junie/allowlist.json.'))
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
      case 'amp':
        findings.push(...amp(agent, ctx, posture))
        break
      case 'goose':
        findings.push(...goose(agent, ctx, posture))
        break
      case 'copilot':
        findings.push(...copilot(agent, ctx))
        break
      case 'antigravity':
        findings.push(...antigravity(agent, ctx, posture))
        break
      case 'antigravity-cli':
        findings.push(...antigravityCli(agent, ctx, posture))
        break
      case 'windsurf':
      case 'trae':
        findings.push(generic(agent, 'low', `${agent.name} has an integrated terminal and an auto run setting stored in its app state, which snuf cannot read. Check the agent settings for auto run or turbo mode.`))
        break
      case 'aider':
        findings.push(...aider(agent, ctx, posture))
        break
      case 'zed':
        findings.push(...zed(agent, ctx, posture))
        break
      case 'continue':
        findings.push(...continueCli(agent, ctx, posture))
        break
      case 'vibe':
        findings.push(...vibe(agent, ctx, posture))
        break
      case 'qwen-code':
        findings.push(...qwen(agent, ctx, posture))
        break
      case 'junie':
        findings.push(...junie(agent, ctx, posture))
        break
      case 'amazon-q':
        findings.push(generic(agent, 'low', 'Amazon Q Developer CLI was folded into Kiro CLI in 2026 and its config was copied to ~/.kiro. If ~/.aws/amazonq is still here, its MCP servers and custom agents may be duplicated in Kiro; review both.'))
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
