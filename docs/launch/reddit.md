# Reddit

Post one subreddit per day. Reply to every comment. Never post the same text twice.

## r/ClaudeAI

Title: I wrote a scanner that shows exactly what Claude Code (and 27 other agents) can reach on your machine

After GitSpawn dropped this month (a cloned repo's .git/config can run code through core.fsmonitor the moment Claude Code runs git status, fixed in 2.1.196) I realised I had no picture of what my agents could actually touch. So I built one.

    npx snuf

It reads ~/.claude.json, settings.json, every .mcp.json, your git config and your GitHub workflows and tells you:

- which MCP servers you load, who publishes them, whether they hold credentials, and whether they are pinned to a version
- whether you're in bypassPermissions or have Bash(*) in an allow list
- whether you've ever started Claude Code from your home directory (I had, which makes ~/.ssh and ~/.aws "the project")
- whether your Claude Code version is patched for GitSpawn
- CLAUDE.md and SKILL.md files with invisible Unicode, prompt injection phrasing, or curl | sh

Read only, no network calls, values masked. Source: github.com/artmikula/snuf

Would love to hear what it finds on your setup and what it misses.

## r/netsec

Title: snuf: local attack surface inventory for AI coding agents (MCP, secrets, git config, CI)

Static scanner, TypeScript, MIT. Enumerates installed agents from their on disk config (28 supported), parses every MCP config format they use (JSON, JSONC, TOML, YAML), classifies each server by publisher, transport, network reach and credential exposure, and rates the host's permission posture per agent.

Sept 2026 additions: repo level .git/config keys that name a program (core.fsmonitor, hooksPath, filters, ! aliases) per Manifold's GitSpawn disclosure, agent version checks against the published fix versions, unpinned and git sourced MCP packages, edit distance 2 typosquat detection against known packages and scopes, and .github/workflows agent actions that accept prompts from non write users.

Zero network, read only, all values masked including in JSON. Scoring is multiplicative so one critical does not saturate the scale. Methodology and severity table are in CLAUDE.md in the repo.

github.com/artmikula/snuf

Interested in false positive reports and in agents I don't cover.

## r/cursor

Title: Check what your Cursor MCP servers and rules can actually reach, in one command

Cursor reads ~/.cursor/mcp.json, project .cursor/mcp.json, .cursorrules and .cursor/rules. Secrets in those project level files end up in git. GitGuardian found 24,008 unique secrets in public MCP config files this year.

npx snuf reads all of them and reports: credentials in MCP configs (masked), unrecognized or unpinned server packages, typosquat lookalikes, rules files with hidden Unicode or curl | sh, and whether the repo's .git/config sets core.fsmonitor (the GitSpawn attack Cursor patched this month).

No network calls, read only. github.com/artmikula/snuf

## r/LocalLLaMA

Title: Running several coding agents plus MCP servers? This shows what they can reach, offline

If you run OpenCode, Goose, Aider, Hermes, Pi, Kimi Code, Qwen Code and a pile of MCP servers, the config sprawl is real. snuf reads all of it (28 agents, JSON/TOML/YAML MCP configs), flags credentials passed to servers, unpinned npx packages, exposed OpenClaw gateways (bind beyond loopback, auth off, version behind 2026.8.1), and rates what each agent can reach. Fully offline, read only.

    npx snuf

github.com/artmikula/snuf
