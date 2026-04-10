# CLAUDE.md — snuf

## What is snuf

snuf is an open-source CLI that sniffs out every AI agent on your machine and shows you exactly what they can access. One command. Full report. No network calls.

It answers the question every developer using AI tools is afraid to ask: **"What have I given AI access to?"**

## The pitch (for README/HN)

You have Claude Code, Cursor, Copilot, Codex, Windsurf, Aider, and OpenClaw installed. Each one has config files, MCP servers, skills, shell access, file permissions, and API keys. Nobody audits the full picture. `snuf` does.

```
npx snuf
```

That's it. One command. Outputs a full security report of your AI agent attack surface.

## Architecture

```
snuf/
├── src/
│   ├── cli.ts                 # Entry point (commander.js)
│   ├── scanner/
│   │   ├── index.ts           # Orchestrator — runs all scanners
│   │   ├── agents.ts          # Detect installed AI agents
│   │   ├── mcp.ts             # Scan MCP server configs
│   │   ├── skills.ts          # Scan Skills directories
│   │   ├── permissions.ts     # Analyze file/dir access scope
│   │   ├── secrets.ts         # Find exposed API keys & tokens
│   │   ├── network.ts         # Check what domains agents can reach
│   │   └── shell.ts           # Assess shell/command execution access
│   ├── agents/                # Agent-specific detection adapters
│   │   ├── claude-code.ts
│   │   ├── cursor.ts
│   │   ├── copilot.ts
│   │   ├── windsurf.ts
│   │   ├── aider.ts
│   │   ├── codex.ts
│   │   ├── openclaw.ts
│   │   ├── opencode.ts
│   │   └── gemini-cli.ts
│   ├── reporter/
│   │   ├── index.ts           # Report orchestrator
│   │   ├── terminal.ts        # Rich terminal output (chalk/box)
│   │   ├── markdown.ts        # Markdown report output
│   │   └── json.ts            # JSON output for CI/CD
│   ├── scoring/
│   │   └── risk.ts            # Risk scoring engine
│   └── types.ts               # Shared types
├── tests/
│   ├── scanner/
│   └── agents/
├── package.json
├── tsconfig.json
├── vitest.config.ts
├── CLAUDE.md
├── README.md
├── LICENSE                    # MIT
└── .github/
    └── workflows/
        └── ci.yml
```

## Tech stack
- **Language**: TypeScript (strict mode)
- **Runtime**: Node.js 20+
- **CLI framework**: commander.js
- **Terminal output**: chalk + boxen (for the pretty report)
- **Testing**: vitest
- **Bundling**: tsup (single binary output)
- **Package manager**: pnpm

## Code style
- ES modules only, never CommonJS
- Named exports, no default exports
- 2-space indentation, no semicolons (prettier with semi: false)
- `const` default, `let` when needed, never `var`
- Early returns over nested if/else
- File names: kebab-case
- Types: PascalCase, no `I` prefix on interfaces
- Minimize dependencies — keep the install fast

## What snuf detects

### 1. Installed AI agents
Scan known paths per OS (macOS, Linux, Windows) for:

| Agent | Config locations |
|---|---|
| Claude Code | `~/.claude/`, `~/.claude.json`, project `CLAUDE.md` files |
| Cursor | `~/.cursor/`, `.cursor/`, `.cursorrules` |
| GitHub Copilot | `~/.config/github-copilot/`, `.github/copilot-instructions.md` |
| Windsurf | `~/.windsurf/`, `.windsurfrules` |
| Aider | `~/.aider.conf.yml`, `.aider.conf.yml` |
| Codex | `~/.codex/`, `AGENTS.md` |
| OpenClaw | `~/.openclaw/`, OpenClaw config dirs |
| OpenCode | `~/.opencode/`, `.opencode/` |
| Gemini CLI | `~/.gemini/`, `GEMINI.md` |

For each agent found, report: version (if detectable), config file paths, and whether it's currently running (check process list).

### 2. MCP servers
Parse all MCP config files and report:
- Server name and transport type (stdio/HTTP)
- Command being executed (and whether it's a known/trusted package)
- Arguments passed
- Environment variables set (flag any that look like secrets)
- Whether the server has network access
- Remote vs local server

Known config locations:
- Claude: `~/.claude/claude_desktop_config.json`, `~/.claude.json` (mcpServers key)
- Cursor: `.cursor/mcp.json`
- Windsurf: `.windsurf/mcp.json`
- Generic: `mcp.json` in project root

### 3. Skills & rules
Scan for:
- CLAUDE.md / AGENTS.md / GEMINI.md content (summarize what instructions agents are following)
- `.claude/skills/` directories
- `.cursor/rules/` directories
- Custom skills that execute commands or access files
- Flag any skill that contains shell commands, network URLs, or file write operations

### 4. File & directory access
For each agent, determine:
- What directories the agent can read/write to
- Whether the agent has access to `~` (home directory)
- Whether `.env` files are accessible
- Whether SSH keys, AWS credentials, or other sensitive dirs are in scope
- Whether the agent can access other projects' directories

### 5. Exposed secrets
Scan agent configs and environment for:
- API keys in MCP server configs (OPENAI_KEY, ANTHROPIC_API_KEY, etc.)
- Tokens in environment variables that agents inherit
- `.env` files in directories agents can access
- SSH keys, AWS credentials in default locations

### 6. Shell access
For each agent, determine:
- Can it execute shell commands? (most can)
- Is it sandboxed in any way?
- What's the permission model? (auto-approve, ask, deny)
- Can it install packages? (`npm install`, `pip install`)
- Can it modify system files?

## Risk scoring

Each finding gets a severity: `info`, `low`, `medium`, `high`, `critical`

Scoring rules:
- Agent installed with default config → `info`
- MCP server running unknown npm package → `medium`
- MCP server with network access + shell execution → `high`
- Exposed API key in config file → `critical`
- Agent has access to SSH keys or cloud credentials → `critical`
- Skill with unrestricted shell commands → `high`
- Agent running as root/admin → `critical`
- No permission model (auto-approve all) → `high`

Overall score: 0-100 (lower is safer)
- 0-20: Clean — minimal exposure
- 21-40: Caution — some permissions to review
- 41-60: Warning — significant attack surface
- 61-80: Danger — multiple high-risk findings
- 81-100: Critical — immediate action needed

## CLI commands

```bash
# Full scan (default)
npx snuf

# Scan with specific output format
npx snuf --format json
npx snuf --format markdown
npx snuf --format terminal  # default

# Scan specific agent only
npx snuf --agent claude-code
npx snuf --agent cursor

# Save report to file
npx snuf --output report.md

# Show only high/critical findings
npx snuf --severity high

# Scan a specific project directory
npx snuf --project /path/to/project

# Quick mode — just show the score
npx snuf --quick
```

## Terminal output design

The terminal report should look like a professional security audit. Use chalk for colors and boxen for framing.

```
╭─────────────────────────────────────────────╮
│                                             │
│   snuf — AI Agent Security Report           │
│   Score: 67/100 ⚠️  WARNING                 │
│                                             │
╰─────────────────────────────────────────────╯

🔍 Agents Found: 4
  ├── Claude Code v1.2.3 ✓ running
  ├── Cursor v0.48 ✓ running  
  ├── GitHub Copilot ✓ installed
  └── Aider v0.82 ○ not running

🔌 MCP Servers: 7
  ├── ✅ @modelcontextprotocol/server-filesystem (known)
  ├── ✅ @modelcontextprotocol/server-github (known)
  ├── ⚠️  custom-db-server (unknown, has shell access)
  ├── ⚠️  my-tool-server (unknown, network + shell)
  └── 🔴 sketchy-mcp (unknown, network + shell + env vars)

🔑 Secrets Exposed: 3
  ├── 🔴 OPENAI_API_KEY in ~/.cursor/mcp.json
  ├── 🔴 ANTHROPIC_API_KEY in environment (inherited by all agents)
  └── ⚠️  DATABASE_URL in .env (accessible by Claude Code)

📁 File Access:
  ├── Claude Code: /Users/dev (full home directory)
  ├── Cursor: /Users/dev/projects (scoped)
  └── ⚠️  SSH keys (~/.ssh/) accessible by 2 agents

🛡️ Top Recommendations:
  1. Move API keys from MCP configs to a secrets manager
  2. Restrict Claude Code's working directory
  3. Audit unknown MCP server: sketchy-mcp
  4. Enable permission prompts for shell commands

Full report: snuf --output report.md
```

## Build commands
```bash
pnpm install
pnpm build            # Build with tsup
pnpm test             # Run vitest
pnpm dev              # Watch mode
pnpm lint             # ESLint
```

## Development workflow
1. Build scanner modules one at a time, test each independently
2. Start with agent detection (most visual, most satisfying)
3. Then MCP scanning (highest security value)
4. Then secrets + permissions (highest shock value)
5. Terminal reporter last (make it pretty at the end)
6. Always run `pnpm test` before committing
7. Use conventional commits: `feat:`, `fix:`, `docs:`, `test:`

## Important constraints
- **ZERO network calls** — snuf never phones home, never sends data anywhere
- **Read-only** — snuf never modifies any config, file, or setting
- **Fast** — full scan should complete in under 3 seconds
- **Works offline** — no API keys needed to run snuf itself
- **Cross-platform** — macOS and Linux primary, Windows best-effort
- **No AI/LLM dependency** — this is a static scanner, not an AI wrapper
- **Minimal deps** — commander, chalk, boxen, fast-glob. That's it.
- **npx-first** — must work perfectly with `npx snuf` (no global install required)
