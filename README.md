# snuf

**Sniff out what the AI agents on your machine can actually reach.**

You installed Claude Code. Then Cursor. Then a few MCP servers from a blog post. Each one can read your files, run shell commands, and hold your API keys. snuf shows you the whole picture in one command.

```
npx snuf
```

<p align="center">
<img src="https://raw.githubusercontent.com/artmikula/snuf/main/docs/screenshot.gif" alt="snuf terminal demo" width="640">
</p>

Read only. Zero network calls. No account, no API key, no AI model involved. It reads config files, prints a report, and exits. Named after the Dutch word for a sniff.

## What it checks

- **Agents.** Every AI coding tool installed, its version, and whether it is running right now. Claude Code, Claude Desktop, Cursor, Copilot, Windsurf, Codex CLI, Gemini CLI, Aider, OpenCode, OpenClaw, Cline, Roo Code, Kiro, Amp, Zed, Continue, Goose, Trae, Qwen Code, Junie.
- **MCP servers.** Every server each agent loads, from the config locations those agents really use, including project scoped entries nested inside `~/.claude.json`, Codex's `config.toml`, and VS Code's `mcp.json`. Which package runs, whether the publisher is recognized, whether it reaches the network, and whether credentials are passed to it.
- **Secrets.** API keys and tokens in MCP configs, in your exported shell environment, in `.env` files, and in agent state files. Plaintext OAuth credential stores that other processes can read. Values are never printed, only masked.
- **Shell and permissions.** Claude Code `defaultMode`, `Bash(*)` in allow lists, hooks that run on every session, `enableAllProjectMcpServers`, missing deny rules. Codex `approval_policy` and `sandbox_mode`. Gemini YOLO mode. Whether you are running as root.
- **File access.** Sessions started with your home directory as the project. SSH keys, cloud credentials, GitHub CLI tokens, npm and PyPI tokens within reach, rated by how easily an agent gets to them without a prompt.
- **Rules and skills.** `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.cursor/rules`, `SKILL.md` files and slash commands. Flags invisible Unicode, prompt injection phrasing, downloads piped into a shell, and privileged commands.

## The report

```
╭────────────────────────────────────────────╮
│                                            │
│   snuf  what your AI agents can reach      │
│                                            │
│   Score  77/100  DANGER                    │
│   0 critical · 4 high · 5 medium · 4 low   │
│                                            │
╰────────────────────────────────────────────╯

🔍 Agents: 4
  ├─ Claude Code v2.1.281  running
  ├─ Cursor v1.7.28  installed
  ├─ Codex CLI v0.154.0  installed
  └─ Gemini CLI  installed

🔌 MCP servers: 3
  ├─ ✅ filesystem (trusted publisher, local process) ~/.cursor/mcp.json
  ├─ 🔴 postgres (unrecognized, local process, 1 credential) ~/.cursor/mcp.json
  └─ ⚠️  node_repl (unrecognized, local process) ~/.codex/config.toml

🔑 Secrets
  ├─  CRIT  DATABASE_URL stored in plaintext in MCP config (postgres)
  ├─  HIGH  OPENAI_API_KEY is exported in your shell environment
  └─  HIGH  Codex CLI auth tokens stored in plaintext ~/.codex/auth.json

🛠  Shell and permissions
  ├─  HIGH  Claude Code pre approves every shell command ~/.claude/settings.json
  └─  LOW   Claude Code has no deny rules ~/.claude/settings.json

📁 File access
  ├─  HIGH  Claude Code has been run with your home directory as the project
  ├─  HIGH  SSH keys reachable by AI agents ~/.ssh
  └─  MED   GitHub CLI token reachable by AI agents ~/.config/gh/hosts.yml

🛡️  Do this first
  1. Move credentials out of MCP config files. Reference them by name (${VAR}) or use the agent keychain.
  2. Turn permission prompts back on. Bypass mode makes prompt injection a remote shell.
  3. Start agents inside a repository, never from your home directory.
```

The score is 0 to 100, lower is safer. Findings combine so that one critical does not pin you at 100, and a clean laptop with the usual `~/.ssh` lands under 20.

## Usage

```bash
npx snuf                                  # full report
npx snuf --quick                          # just the score
npx snuf --severity high                  # hide anything below high
npx snuf --agent claude-code              # one agent only
npx snuf --project ~/work/app             # scan another project directory
npx snuf --format markdown --output snuf-report.md
npx snuf --format json                    # machine readable, values masked
npx snuf --fail-on high                   # exit 1 for CI when anything high or critical is found
```

`--output` infers the format from the extension, so `--output report.json` works without `--format`.

## What snuf does not do

- **No network calls.** Nothing is sent anywhere. Check the source, it is small.
- **No writes.** The only file snuf ever creates is the one you name with `--output`.
- **No secrets in output.** Values are masked to a prefix, a suffix, and a length, even in JSON.
- **No AI.** Static checks only. It runs in well under a second.

Windows support is best effort. Config paths are checked, but process detection and version lookups are limited.

## Running it on a team

Have each developer run `npx snuf --format json --output snuf.json` and review the file before sharing it. Since values are masked, the JSON is safe to attach to a ticket. If you want someone to go through the results with you and write up what to change, [Centipede Software](https://centipede.dev/services/ai-agent-security-audit/) does fixed price audits built on this tool.

## Why this exists

I ship with Claude Code every day. When I finally looked at what it, and the four other agents on my laptop, could reach, I did not like the answer. There were tools for scanning a single MCP config, but nothing that answered the actual question: what have I given these things access to? snuf is that answer, in under a second, without sending your configs to anyone.

## Contributing

Adding an agent is one entry in `src/agents/index.ts` and, if it has MCP config, one line in `src/scanner/mcp.ts`. See [CONTRIBUTING.md](./CONTRIBUTING.md).

## License

MIT
