---
title: What the AI agents on your laptop can actually reach (and one command to find out)
published: false
tags: security, ai, devtools, opensource
---

In September 2026 a security firm showed that a git repository's own `.git/config` can run code inside Claude Code, Codex, Cursor, Goose and three other agents. The key is `core.fsmonitor`. Git runs whatever it names on every `git status`, and agents run `git status` constantly in the background to figure out your branch and changed files. It fires before the "do you trust this folder" prompt and outside whatever sandbox the agent claims to have.

A week earlier, a malicious MCP server called Deadbugz was pushed to 23 projects in 74 minutes. It ships two harmless tools, behaves for exactly three calls, then rewrites its own tool descriptions into instructions to look for SSH keys, AWS credentials and shell history.

And GitGuardian counted 24,008 unique secrets in public MCP config files this year. 2,117 of them were still valid.

None of this is exotic. It's config files. Which is the point: the attack surface of AI coding tools is mostly text files in your home directory, and almost nobody has read them all.

## The question nobody could answer

I run Claude Code daily. I also have Cursor, Codex, Gemini CLI and a couple of desktop apps installed, plus MCP servers I added from blog posts months ago. When I sat down to answer "what can all of this reach?", I couldn't. The answer was spread over a dozen files in five formats.

So I wrote a scanner. It's called snuf, it's one command, and it never touches the network.

```
npx snuf
```

## What it reads

**Agents.** It knows the on disk footprint of 28 tools: Claude Code and Claude Desktop, Cursor, Copilot, Windsurf, Codex CLI, Gemini CLI, Antigravity, Aider, OpenCode, OpenClaw, Cline, Roo Code, Kiro, Amp, Zed, Continue, Goose, Trae, Qwen Code, Junie, Factory Droid, Pi, Kimi Code, Hermes, Grok Build, Amazon Q and Mistral Vibe. For each one it reports the version, whether it's running, and where its config lives.

**MCP servers.** Every config location those agents really use, including the project scoped entries nested inside `~/.claude.json`, Codex's TOML, Hermes' YAML and VS Code's `servers` key. For each server: the package it runs, whether the publisher is recognised, whether it reaches the network, and whether credentials are passed in its environment.

**Supply chain.** Package names one or two characters off a well known server. Servers installed straight from a git URL. Servers started with `npx` and no pinned version, which means every agent start resolves whatever was published most recently.

**Secrets.** Keys in MCP configs, in your exported shell environment, in `.env` files, and in the plaintext OAuth stores several agents keep in your home directory. Values are never printed, only a masked prefix and length.

**Permissions.** Claude Code `defaultMode`, `Bash(*)` in allow lists, hooks that run on every session. Codex `approval_policy` and `sandbox_mode`. Gemini YOLO mode. Droid autonomy level. OpenClaw gateway bound beyond localhost with auth off.

**What's in reach.** Whether you've ever started an agent from your home directory (I had). Whether SSH keys, cloud credentials, the GitHub CLI token and npm tokens are within a single approved read.

**Git config.** The GitSpawn keys: `core.fsmonitor`, `core.hooksPath`, `!` aliases, filters, diff drivers. And whether the agent you have installed is above the patched version.

**CI.** Agent actions in `.github/workflows` that accept prompts from any GitHub account, run on issue or PR text with write permissions, or float on a tag instead of a commit SHA.

## What it found on my machine

Score 76 out of 100, where lower is better.

- An API key in an MCP config I'd forgotten I'd written
- Claude Code had been started from `~` at some point, which makes every credential on the disk "the project"
- 37 pre approved shell patterns in a project settings file, two of which can reach the network
- Codex auth tokens in a plaintext JSON file readable by every process running as me
- Grok Build installed at a version with no GitSpawn fix

None of these were a breach. All of them were things I'd have said "no, I don't do that" about.

## Design constraints

Zero network calls. Read only. No account, no API key, no model. It has four runtime dependencies. It runs in well under a second. JSON output is safe to attach to a ticket because every value is masked.

The score is multiplicative. Each finding removes a fraction of the remaining safety, so one critical doesn't pin you at 100 and a clean laptop with the usual `~/.ssh` lands under 20.

## Run it

```
npx snuf                    # full report
npx snuf --severity high    # only the bad stuff
npx snuf --format json      # for CI, with --fail-on high
```

Source: github.com/artmikula/snuf. MIT. If it misses an agent you use, an issue with the config path is all it takes.
