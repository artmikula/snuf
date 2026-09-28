import { describe, it, expect, afterEach } from 'vitest'
import { scanShell } from '../../src/scanner/shell.js'
import { sandbox, agent, type Sandbox } from '../helpers.js'

let box: Sandbox
afterEach(() => box?.cleanup())

describe('scanShell', () => {
  it('reports prompts intact for a default Claude Code install', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { deny: ['Read(./.env)'] } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(false)
    expect(findings.some((f) => f.title.includes('likely runs in auto mode'))).toBe(true)
  })

  it('treats pinned auto mode as low and disableAutoMode as prompts intact', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'auto', deny: ['Read(./.env)'] } }))
    const auto = await scanShell(box.ctx([agent('claude-code')]))
    expect(auto.findings.find((f) => f.title.includes('runs in auto mode'))?.severity).toBe('low')
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { disableAutoMode: 'disable', deny: ['Read(./.env)'] } }))
    const manual = await scanShell(box.ctx([agent('claude-code')]))
    expect(manual.findings.find((f) => f.title.includes('prompts before'))?.severity).toBe('info')
  })

  it('flags bypassPermissions as high and marks posture unprompted', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('without permission prompts'))?.severity).toBe('high')
  })

  it('flags Bash(*) in the allow list', async () => {
    box = sandbox()
    box.write('home/work/app/.claude/settings.local.json', JSON.stringify({ permissions: { allow: ['Bash(*)', 'Read'] } }))
    const { findings, posture } = await scanShell(box.ctx([agent('claude-code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.some((f) => f.title.includes('every shell command'))).toBe(true)
  })

  it('counts hooks and flags enableAllProjectMcpServers', async () => {
    box = sandbox()
    box.write('home/work/app/.claude/settings.json', JSON.stringify({
      enableAllProjectMcpServers: true,
      hooks: { SessionStart: [{ hooks: [{ type: 'command', command: 'curl x | sh' }] }], PreToolUse: [{ matcher: 'Bash', hooks: [{ type: 'command', command: 'echo' }] }] },
    }))
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    expect(findings.find((f) => f.title.includes('hook'))?.title).toContain('2 Claude Code hooks')
    expect(findings.some((f) => f.title.includes('auto trusts every project MCP server'))).toBe(true)
  })

  it('reads codex approval and sandbox settings', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n')
    const { findings, posture } = await scanShell(box.ctx([agent('codex')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.filter((f) => f.severity === 'high')).toHaveLength(2)
  })

  it('flags codex network access and a trusted home directory', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', `approval_policy = "on-request"\nsandbox_mode = "workspace-write"\n\n[sandbox_workspace_write]\nnetwork_access = true\n\n[projects."${box.home}"]\ntrust_level = "trusted"\n\n[projects."${box.project}"]\ntrust_level = "trusted"\n`)
    const { findings } = await scanShell(box.ctx([agent('codex')]))
    expect(findings.find((f) => f.title.includes('network access'))?.severity).toBe('medium')
    const trust = findings.find((f) => f.title.includes('trusts your home'))
    expect(trust?.severity).toBe('high')
    expect(trust?.detail).not.toContain(box.project)
  })

  it('reads gemini yolo mode', async () => {
    box = sandbox()
    box.write('home/.gemini/settings.json', JSON.stringify({ general: { yolo: true } }))
    const { findings } = await scanShell(box.ctx([agent('gemini-cli')]))
    expect(findings[0]!.severity).toBe('high')
  })
})

describe('scanShell cursor cli and opencode', () => {
  it('flags Cursor CLI unrestricted approval mode and Shell(*)', async () => {
    box = sandbox()
    box.write('home/.cursor/cli-config.json', JSON.stringify({ version: 1, approvalMode: 'unrestricted', permissions: { allow: ['Shell(*)'] } }))
    const { findings, posture } = await scanShell(box.ctx([agent('cursor', 'Cursor')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.filter((f) => f.severity === 'high')).toHaveLength(2)
  })

  it('falls back to the generic cursor note without CLI config', async () => {
    box = sandbox()
    const { findings } = await scanShell(box.ctx([agent('cursor', 'Cursor')]))
    expect(findings).toHaveLength(1)
    expect(findings[0]!.severity).toBe('low')
  })

  it('reads OpenCode permission rules including wildcard objects', async () => {
    box = sandbox()
    box.write('home/.config/opencode/opencode.json', JSON.stringify({ permission: { '*': 'allow', edit: 'ask', bash: { '*': 'ask', 'git *': 'allow', 'curl *': 'allow' } } }))
    const { findings, posture } = await scanShell(box.ctx([agent('opencode', 'OpenCode')]))
    expect(posture.unprompted).toBe(false)
    expect(findings.some((f) => f.title.includes('outside the project'))).toBe(true)
    expect(findings.find((f) => f.title.includes('risky shell'))?.detail).toContain('curl *')
    expect(findings.some((f) => f.title.includes('without asking') && f.title.includes('shell'))).toBe(false)
  })

  it('flags OpenCode bash allow as high', async () => {
    box = sandbox()
    box.write('home/work/app/opencode.json', JSON.stringify({ permission: { bash: 'allow' } }))
    const { findings, posture } = await scanShell(box.ctx([agent('opencode', 'OpenCode')]))
    expect(posture.unprompted).toBe(true)
    expect(findings[0]!.severity).toBe('high')
  })
})

describe('scanShell kimi and hermes', () => {
  it('reads Kimi Code yolo mode and allow rules', async () => {
    box = sandbox()
    box.write('home/.kimi-code/config.toml', '[permission]\ndefault_permission_mode = "yolo"\ndangerous_command_guard = false\n\n[[permission.rules]]\ndecision = "allow"\npattern = "Bash"\nscope = "user"\n')
    const { findings, posture } = await scanShell(box.ctx([agent('kimi-code', 'Kimi Code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.map((f) => f.severity).sort()).toEqual(['high', 'high', 'medium'])
  })

  it('reports Hermes sandbox backend as info and local as medium', async () => {
    box = sandbox()
    box.write('home/.hermes/config.yaml', 'terminal:\n  backend: docker\n')
    const sandboxed = await scanShell(box.ctx([agent('hermes', 'Hermes Agent')]))
    expect(sandboxed.findings[0]!.severity).toBe('info')
    box.write('home/.hermes/config.yaml', 'agent:\n  dangerous_command_approval: false\nterminal:\n  backend: local\n')
    const local = await scanShell(box.ctx([agent('hermes', 'Hermes Agent')]))
    expect(local.findings.map((f) => f.severity)).toEqual(['medium', 'medium'])
  })
})

describe('scanShell openclaw and factory', () => {
  it('flags an exposed unauthenticated OpenClaw gateway as critical', async () => {
    box = sandbox()
    box.write('home/.openclaw/openclaw.json', JSON.stringify({ gateway: { bind: 'lan', auth: { mode: 'none' } } }))
    const { findings, posture } = await scanShell(box.ctx([agent('openclaw', 'OpenClaw')]))
    expect(findings.find((f) => f.title.includes('no authentication'))?.severity).toBe('critical')
    expect(posture.unprompted).toBe(true)
  })

  it('rates loopback with auth none as medium and old versions as high', async () => {
    box = sandbox()
    box.write('home/.openclaw/openclaw.json', JSON.stringify({ gateway: { bind: 'loopback', auth: { mode: 'none' } } }))
    const { findings } = await scanShell(box.ctx([{ ...agent('openclaw', 'OpenClaw'), version: '2026.3.11' }]))
    expect(findings.find((f) => f.title.includes('auth is disabled'))?.severity).toBe('medium')
    expect(findings.find((f) => f.title.includes('behind the last security release'))?.severity).toBe('high')
  })

  it('is quiet for a default loopback token OpenClaw', async () => {
    box = sandbox()
    box.write('home/.openclaw/openclaw.json', JSON.stringify({ gateway: { bind: 'loopback', auth: { mode: 'token', token: 'abc' } } }))
    const { findings } = await scanShell(box.ctx([{ ...agent('openclaw', 'OpenClaw'), version: '2026.9.1' }]))
    expect(findings.filter((f) => f.severity !== 'medium')).toEqual([])
  })

  it('reads Factory Droid autonomy level', async () => {
    box = sandbox()
    box.write('home/.factory/settings.json', JSON.stringify({ sessionDefaultSettings: { autonomyLevel: 'high' }, commandAllowlist: ['git status', 'curl *'] }))
    const { findings, posture } = await scanShell(box.ctx([agent('factory', 'Factory Droid')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('full autonomy'))?.severity).toBe('high')
    expect(findings.find((f) => f.title.includes('risky command'))?.detail).toContain('curl *')
  })
})

describe('scanShell gemini trusted folders', () => {
  it('flags a trusted home directory, including via TRUST_PARENT', async () => {
    box = sandbox()
    box.write('home/.gemini/trustedFolders.json', JSON.stringify({ config: { [box.project]: 'TRUST_FOLDER', [box.home + '/work']: 'TRUST_PARENT', '/somewhere/else': 'DO_NOT_TRUST' } }))
    const { findings } = await scanShell(box.ctx([agent('gemini-cli', 'Gemini CLI')]))
    const trust = findings.find((f) => f.title.includes('trusts your home'))
    expect(trust?.severity).toBe('high')
    expect(trust?.detail).toContain(box.home + '/work')
    expect(trust?.detail).not.toContain(box.project + ',')
  })

  it('stays quiet when only project folders are trusted', async () => {
    box = sandbox()
    box.write('home/.gemini/trustedFolders.json', JSON.stringify({ [box.project]: 'TRUST_FOLDER' }))
    const { findings } = await scanShell(box.ctx([agent('gemini-cli', 'Gemini CLI')]))
    expect(findings.filter((f) => !f.title.includes('stopped serving')).map((f) => f.severity)).toEqual(['info'])
  })
})

describe('scanShell grok build', () => {
  it('flags always-approve, auto_allow_bash without a sandbox, and Bash(*)', async () => {
    box = sandbox()
    box.write('home/.grok/config.toml', '[ui]\npermission_mode = "always-approve"\n\n[sandbox]\nprofile = "off"\nauto_allow_bash = true\n\n[permission]\nallow = ["Bash(*)", "Read(src/**)"]\n')
    const { findings, posture } = await scanShell(box.ctx([agent('grok', 'Grok Build')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.filter((f) => f.severity === 'high')).toHaveLength(3)
  })

  it('rates auto_allow_bash inside a sandbox profile as medium', async () => {
    box = sandbox()
    box.write('home/.grok/config.toml', '[sandbox]\nprofile = "workspace"\nauto_allow_bash = true\n')
    const { findings } = await scanShell(box.ctx([agent('grok', 'Grok Build')]))
    expect(findings.find((f) => f.title.includes('without asking'))?.severity).toBe('medium')
  })

  it('reads codex approvals_reviewer', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', 'approvals_reviewer = "auto_review"\n')
    const { findings } = await scanShell(box.ctx([agent('codex')]))
    expect(findings.find((f) => f.title.includes('reviews its own'))?.severity).toBe('medium')
  })
})

describe('scanShell claude code sandbox', () => {
  it('downgrades bypass mode when the sandbox is on and flags weakened sandbox settings', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({
      permissions: { defaultMode: 'bypassPermissions', deny: ['Read(./.env)'] },
      sandbox: { enabled: true, excludedCommands: ['git', 'curl'], network: { allowedDomains: ['*'] }, credentials: { allowPlaintextInject: true } },
    }))
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    expect(findings.find((f) => f.title.includes('without permission prompts'))?.severity).toBe('medium')
    expect(findings.find((f) => f.title.includes('escape hatch'))?.severity).toBe('low')
    expect(findings.find((f) => f.title.includes('excluded from'))?.detail).toContain('curl')
    expect(findings.some((f) => f.title.includes('every network domain'))).toBe(true)
    expect(findings.some((f) => f.title.includes('plaintext'))).toBe(true)
  })

  it('reports a locked sandbox as info', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { deny: ['Read(./.env)'] }, sandbox: { enabled: true, allowUnsandboxedCommands: false } }))
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    expect(findings.find((f) => f.title.includes('locked'))?.severity).toBe('info')
  })
})

describe('scanShell kiro and claude allow list extras', () => {
  it('parses Kiro permissions.yaml and agent allowedTools', async () => {
    box = sandbox()
    box.write('home/.kiro/settings/permissions.yaml', 'rules:\n  - capability: shell\n    match: ["git *", "curl *"]\n    effect: allow\n  - capability: fs_write\n    match: ["~/**"]\n    effect: allow\n')
    box.write('home/.kiro/agents/ops.json', JSON.stringify({ name: 'ops', allowedTools: ['*'] }))
    const { findings, posture } = await scanShell(box.ctx([agent('kiro', 'Kiro')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('risky shell'))?.detail).toContain('curl *')
    expect(findings.some((f) => f.title.includes('writes outside'))).toBe(true)
    expect(findings.find((f) => f.title.includes('trusts shell'))?.severity).toBe('high')
  })

  it('flags a blanket Kiro shell allow as high', async () => {
    box = sandbox()
    box.write('home/.kiro/settings/permissions.yaml', 'rules:\n  - capability: all\n    effect: allow\n')
    const { findings } = await scanShell(box.ctx([agent('kiro', 'Kiro')]))
    expect(findings[0]!.severity).toBe('high')
  })

  it('flags whole MCP server allow rules and reports hardening', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { allow: ['mcp__github', 'mcp__puppeteer__*', 'mcp__slack__post_message', 'WebFetch(domain:*)'], deny: ['Read(./.env)'], disableBypassPermissionsMode: 'disable', blockReadsOutsideWorkingDirectories: true } }))
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    const mcp = findings.find((f) => f.title.includes('MCP server'))
    expect(mcp?.title).toContain('2 MCP servers')
    expect(mcp?.detail).not.toContain('slack')
    expect(findings.some((f) => f.title.includes('pre approves WebFetch'))).toBe(true)
    expect(findings.find((f) => f.title.includes('hardened'))?.title).toContain('bypass mode disabled')
  })
})

describe('scanShell amp, goose, copilot', () => {
  it('reads Amp dangerouslyAllowAll, permissions and allowlist', async () => {
    box = sandbox()
    box.write('home/.config/amp/settings.json', JSON.stringify({ 'amp.permissions': [{ tool: 'Bash', action: 'allow' }], 'amp.commands.allowlist': ['git status', 'curl *'] }))
    const { findings, posture } = await scanShell(box.ctx([agent('amp', 'Amp')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.map((f) => f.severity).sort()).toEqual(['high', 'medium'])
  })

  it('treats a missing GOOSE_MODE as auto and smart_approve as low', async () => {
    box = sandbox()
    const saved = process.env['GOOSE_MODE']
    delete process.env['GOOSE_MODE']
    box.write('home/.config/goose/config.yaml', 'GOOSE_PROVIDER: anthropic\n')
    const missing = await scanShell(box.ctx([agent('goose', 'Goose')]))
    expect(missing.findings[0]!.severity).toBe('medium')
    expect(missing.posture.unprompted).toBe(true)
    box.write('home/.config/goose/config.yaml', 'GOOSE_MODE: smart_approve\n')
    const smart = await scanShell(box.ctx([agent('goose', 'Goose')]))
    expect(smart.findings[0]!.severity).toBe('low')
    box.write('home/.config/goose/config.yaml', 'GOOSE_MODE: auto\n')
    const auto = await scanShell(box.ctx([agent('goose', 'Goose')]))
    expect(auto.findings[0]!.severity).toBe('high')
    if (saved !== undefined) process.env['GOOSE_MODE'] = saved
  })

  it('flags Copilot CLI trusted_folders that include home', async () => {
    box = sandbox()
    box.write('home/.copilot/config.json', JSON.stringify({ trusted_folders: [box.project, box.home] }))
    const { findings } = await scanShell(box.ctx([agent('copilot', 'GitHub Copilot')]))
    expect(findings[0]!.severity).toBe('high')
    expect(findings[0]!.detail).not.toContain(box.project + ',')
  })
})

describe('scanShell antigravity', () => {
  it('reads the IDE autoExecutionPolicy and permission grants', async () => {
    box = sandbox()
    box.write('home/.gemini/config/config.json', JSON.stringify({ userSettings: { autoExecutionPolicy: 'Always Proceed', enableTerminalSandbox: false, nonWorkspaceFileAccessPolicy: 'Always Proceed' } }))
    const { findings, posture } = await scanShell(box.ctx([agent('antigravity', 'Antigravity')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.map((f) => f.severity).sort()).toEqual(['high', 'medium'])
  })

  it('downgrades to medium when the terminal sandbox is on', async () => {
    box = sandbox()
    box.write('home/.gemini/antigravity-cli/settings.json', JSON.stringify({ enableTerminalSandbox: true, permissions: { allow: ['command'] } }))
    const { findings } = await scanShell(box.ctx([agent('antigravity-cli', 'Antigravity CLI')]))
    expect(findings[0]!.severity).toBe('medium')
  })
})

describe('scanShell codex execution policy', () => {
  it('parses prefix_rule files and rates them', async () => {
    box = sandbox()
    box.write('home/.codex/config.toml', 'approval_policy = "on-request"\n')
    box.write('home/.codex/rules/default.rules', `prefix_rule(
    pattern = ["gh", "pr", "view"],
    decision = "allow",
    match = ["gh pr view 7888"],
)

prefix_rule(
    pattern = ["curl"],
    decision = "allow",
)

prefix_rule(pattern=["curl", "-L", "https://example.com/health"], decision="allow")
prefix_rule(pattern=["rm", "-rf", ".wrangler"], decision="allow")
prefix_rule(pattern=["python3", "-m", "http.server"], decision="allow")
prefix_rule(pattern=["/bin/zsh", "-lc", "'/Applications/App' --flag"], decision="allow")

prefix_rule(
    pattern = ["rm", "-rf"],
    decision = "deny",
)
`)
    const { findings } = await scanShell(box.ctx([agent('codex')]))
    const risky = findings.find((f) => f.title.includes('risky command prefix'))
    expect(risky?.severity).toBe('medium')
    expect(risky?.title).toContain('1 risky')
    expect(risky?.detail).toContain('curl')
    expect(risky?.detail).not.toContain('rm -rf')
    expect(risky?.detail).not.toContain('http.server')
    expect(findings.some((f) => f.title.includes('bare shell'))).toBe(false)
  })

  it('flags a bare shell allow as high', async () => {
    box = sandbox()
    box.write('home/work/app/.codex/rules/team.rules', 'prefix_rule(pattern = ["/bin/zsh", "-lc"], decision = "allow")\n')
    box.write('home/.codex/config.toml', '')
    const { findings, posture } = await scanShell(box.ctx([agent('codex')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('bare shell'))?.severity).toBe('high')
  })
})

describe('scanShell aider and zed', () => {
  it('reads aider yes-always, inline keys and auto-test', async () => {
    box = sandbox()
    box.write('home/work/app/.aider.conf.yml', 'yes-always: true\nauto-test: true\nopenai-api-key: sk-proj-' + 'k'.repeat(40) + '\n')
    const { findings, posture } = await scanShell(box.ctx([agent('aider', 'Aider')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('yes to every'))?.detail).toContain('project scoped')
    expect(findings.find((f) => f.category === 'secret')?.severity).toBe('critical')
    expect(JSON.stringify(findings)).not.toContain('kkkkkkkkkk')
    expect(findings.some((f) => f.title.includes('auto-test'))).toBe(true)
  })

  it('reads zed legacy and modern auto approve settings', async () => {
    box = sandbox()
    box.write('home/.config/zed/settings.json', JSON.stringify({ agent: { always_allow_tool_actions: true } }))
    const legacy = await scanShell(box.ctx([agent('zed', 'Zed')]))
    expect(legacy.findings[0]!.severity).toBe('high')
    box.write('home/.config/zed/settings.json', JSON.stringify({ agent: { tool_permissions: { default: 'allow' } } }))
    const modern = await scanShell(box.ctx([agent('zed', 'Zed')]))
    expect(modern.findings[0]!.severity).toBe('high')
    box.write('home/.config/zed/settings.json', JSON.stringify({ agent: { tool_permissions: { default: 'confirm' } } }))
    const safe = await scanShell(box.ctx([agent('zed', 'Zed')]))
    expect(safe.findings[0]!.severity).toBe('low')
  })
})

describe('scanShell continue, vibe, qwen', () => {
  it('reads Continue permissions.yaml allow lists', async () => {
    box = sandbox()
    box.write('home/.continue/permissions.yaml', 'allow:\n  - Read()\n  - Bash(git *)\n  - Bash(curl *)\nask:\n  - Write()\n')
    const { findings } = await scanShell(box.ctx([agent('continue', 'Continue')]))
    expect(findings.find((f) => f.title.includes('risky shell'))?.detail).toContain('curl')
    box.write('home/.continue/permissions.yaml', 'allow:\n  - Bash\n')
    const all = await scanShell(box.ctx([agent('continue', 'Continue')]))
    expect(all.posture.unprompted).toBe(true)
  })

  it('reads Vibe default agent and trusted folders', async () => {
    box = sandbox()
    box.write('home/.vibe/config.toml', 'agent = "auto-approve"\n')
    box.write('home/.vibe/trusted_folders.toml', `trusted = ["${box.home}"]\n`)
    const { findings, posture } = await scanShell(box.ctx([agent('vibe', 'Mistral Vibe')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.filter((f) => f.severity === 'high')).toHaveLength(2)
  })

  it('reads Qwen approvalMode and trusted folders', async () => {
    box = sandbox()
    box.write('home/.qwen/settings.json', JSON.stringify({ tools: { approvalMode: 'yolo' } }))
    box.write('home/.qwen/trustedFolders.json', JSON.stringify({ [box.home]: 'TRUST_FOLDER' }))
    const { findings, posture } = await scanShell(box.ctx([agent('qwen-code', 'Qwen Code')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.map((f) => f.severity)).toEqual(['high', 'high'])
  })
})

describe('scanShell junie', () => {
  it('reads brave mode, byok keys, and allowlist rules', async () => {
    box = sandbox()
    box.write('home/.junie/config.json', JSON.stringify({ brave: true, byok: { openai: 'sk-' + 'j'.repeat(40) }, hooks: [{ on: 'start', run: 'echo hi' }] }))
    box.write('home/.junie/allowlist.json', JSON.stringify({ defaultBehavior: 'ask', rules: { executables: { rules: [{ prefix: 'git', action: 'allow' }, { prefix: 'curl', action: 'allow' }] }, readSecretFile: { rules: [{ pattern: '**/.env', action: 'allow' }] }, readOutsideProject: { rules: [{ pattern: '/**', action: 'allow' }] } } }))
    const { findings, posture } = await scanShell(box.ctx([agent('junie', 'JetBrains Junie')]))
    expect(posture.unprompted).toBe(true)
    expect(findings.find((f) => f.title.includes('brave mode'))?.severity).toBe('high')
    expect(findings.find((f) => f.category === 'secret')?.severity).toBe('critical')
    expect(JSON.stringify(findings)).not.toContain('jjjjjjjjjj')
    expect(findings.find((f) => f.title.includes('risky command'))?.detail).toContain('curl')
    expect(findings.find((f) => f.title.includes('secret files'))?.severity).toBe('high')
    expect(findings.some((f) => f.title.includes('anywhere outside'))).toBe(true)
  })

  it('flags a blanket executables rule', async () => {
    box = sandbox()
    box.write('home/.junie/allowlist.json', JSON.stringify({ rules: { executables: { rules: [{ prefix: '', action: 'allow' }] } } }))
    const { findings } = await scanShell(box.ctx([agent('junie', 'JetBrains Junie')]))
    expect(findings[0]!.severity).toBe('high')
  })
})

describe('scanShell cursor hooks', () => {
  it('rates project hooks medium and user hooks low', async () => {
    box = sandbox()
    box.write('home/work/app/.cursor/hooks.json', JSON.stringify({ version: 1, hooks: { beforeShellExecution: [{ command: './hooks/log.sh' }], afterFileEdit: [{ command: 'prettier' }] } }))
    box.write('home/.cursor/hooks.json', JSON.stringify({ version: 1, hooks: { stop: [{ command: 'say done' }] } }))
    const { findings } = await scanShell(box.ctx([agent('cursor', 'Cursor')]))
    expect(findings.find((f) => f.title.includes('2 Cursor hooks'))?.severity).toBe('medium')
    expect(findings.find((f) => f.title.includes('1 Cursor hook '))?.severity).toBe('low')
  })
})

describe('scanShell claude plugins and channels', () => {
  it('flags third party marketplaces and channels', async () => {
    box = sandbox()
    box.write('home/.claude/settings.json', JSON.stringify({ permissions: { defaultMode: 'bypassPermissions' } }))
    box.write('home/.claude/plugins/known_marketplaces.json', JSON.stringify({ 'claude-plugins-official': { source: { source: 'github', repo: 'anthropics/claude-plugins-official' } }, 'random-market': { source: { source: 'github', repo: 'someone/market' } } }))
    box.write('home/.claude/plugins/installed_plugins.json', JSON.stringify({ version: 2, plugins: { 'superpowers@claude-plugins-official': [{}], 'thing@random-market': [{}] } }))
    box.write('home/.claude/channels/telegram/.env', 'TELEGRAM_BOT_TOKEN=123456:ABCDEFabcdef1234567890abcdefABCDEF12\n')
    const { findings } = await scanShell(box.ctx([agent('claude-code')]))
    const market = findings.find((f) => f.title.includes('marketplace'))
    expect(market?.severity).toBe('medium')
    expect(market?.detail).toContain('someone/market')
    expect(market?.detail).toContain('thing@random-market')
    expect(findings.find((f) => f.title.includes('driven from telegram'))?.severity).toBe('high')
  })
})
