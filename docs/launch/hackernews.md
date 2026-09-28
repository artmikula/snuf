# Hacker News

Post Tuesday to Thursday, 9 to 11am US Eastern. Post the first comment within a minute of submitting.

## Title

Show HN: snuf – see what the AI agents on your machine can actually reach

## URL

https://github.com/artmikula/snuf

## First comment

I ship with Claude Code every day. This month Manifold published GitSpawn: a cloned repo's own .git/config can set core.fsmonitor to a command, and the moment an agent runs git status in the background it executes, before any trust prompt, outside any sandbox. Seven agents were hit, four had no fix at publication. A week before that, Deadbugz shipped a malicious MCP server that behaves for three tool calls and then goes hunting for SSH keys.

I wanted one command that answers "what have I actually handed these things?" so I wrote snuf.

    npx snuf

It walks the config files of 28 agents (Claude Code, Cursor, Codex, Copilot, Gemini CLI, OpenClaw, Goose, Droid, Pi, and so on), every MCP config they load, your git config, and your .github/workflows, and prints a report:

- MCP servers: package, publisher, whether it reaches the network, whether credentials are in its env, typosquat lookalikes, unpinned npx installs
- Secrets in MCP configs, shell env, .env files, and plaintext OAuth stores
- Permission posture: bypass modes, Bash(*) allow lists, YOLO flags, Codex sandbox, Droid autonomy level
- What's in reach: home directory as project, ~/.ssh, ~/.aws, gh tokens
- Repo .git/config keys that name a program (fsmonitor, hooksPath, filters, aliases) and whether your agent version is patched
- CI workflows where any GitHub account can prompt your agent

Read only, zero network calls, values masked in every output format. On my own machine it found an API key in an MCP config I'd forgotten about and that I'd once started Claude Code from my home directory, which makes every credential on the disk "in scope".

Source is small and boring on purpose. Happy to answer questions about specific detections or what's missing.
