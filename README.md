# snuf

**Sniff out what AI agents can actually do on your machine.**

You have Claude Code, Cursor, Copilot, and 4 other AI tools installed. Each has MCP servers, shell access, API keys, and file permissions. Nobody audits the full picture.

```
npx snuf
```

<p align="center">
<img src="docs/screenshot.gif" alt="snuf terminal demo" width="600">
</p>

## What it finds

- **Installed agents** — Every AI coding tool on your machine, its config, and whether it's running
- **MCP servers** — What servers are connected, what commands they run, and whether they're known or unknown
- **Exposed secrets** — API keys in configs, tokens in environment variables, credentials agents can access
- **File access** — What directories each agent can read and write, including your SSH keys and cloud credentials
- **Shell access** — Which agents can run arbitrary commands, install packages, and modify your system
- **Skills & rules** — What instructions your agents are following and whether any contain risky operations

## The report

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
  ├── ✅ server-filesystem (known)
  ├── ⚠️  custom-db-server (unknown, has shell access)
  └── 🔴 sketchy-mcp (unknown, network + shell + env vars)

🔑 Secrets Exposed: 3
  ├── 🔴 OPENAI_API_KEY in ~/.cursor/mcp.json
  ├── 🔴 ANTHROPIC_API_KEY in environment
  └── ⚠️  DATABASE_URL in .env (accessible by Claude Code)
```

## Install

```bash
# Run instantly — no install needed
npx snuf

# Or install globally
npm install -g snuf
```

## Options

```bash
npx snuf                        # Full scan, terminal output
npx snuf --quick                # Just the score
npx snuf --format json          # JSON output for CI/CD
npx snuf --format markdown      # Markdown report
npx snuf --output report.md     # Save to file
npx snuf --agent claude-code    # Scan specific agent
npx snuf --severity high        # Only high/critical findings
```

## What snuf does NOT do

- **No network calls** — snuf never phones home or sends your data anywhere
- **No file modifications** — read-only, always
- **No AI/LLM calls** — static analysis only, no API keys needed
- **No data collection** — everything stays on your machine

## Why this exists

I spent years building AI trustworthiness assessment frameworks at [ThinkforBL](https://thinkforbl.com) — evaluating AI systems for Korean defense and government agencies. The assessment methodology I used there had 51 domains and 1,700+ evaluation criteria.

Then I looked at my own machine. I had 5 AI agents installed, 12 MCP servers connected, and API keys scattered across config files. I had no idea what attack surface I'd created.

snuf is the 2-minute version of a trust assessment — built for developers who use AI tools daily and want to know what they've actually exposed.

## Supported agents

| Agent | Detection | MCP Scan | Permissions |
|-------|-----------|----------|-------------|
| Claude Code | ✅ | ✅ | ✅ |
| Cursor | ✅ | ✅ | ✅ |
| GitHub Copilot | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Codex CLI | ✅ | ✅ | ✅ |
| Aider | ✅ | — | ✅ |
| OpenClaw | ✅ | ✅ | ✅ |
| OpenCode | ✅ | ✅ | ✅ |
| Gemini CLI | ✅ | ✅ | ✅ |

## Contributing

PRs welcome. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT
