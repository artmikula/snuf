# snuf handoff

Written 2026-09-28 for whoever (human or AI agent) picks this up next. Read this before touching anything.

## What snuf is

A read only, zero network CLI that inventories every AI coding agent on a developer machine and reports what each one can reach. `npx snuf` prints a 0 to 100 risk score (lower is safer) plus findings grouped by secrets, shell and permissions, file access, MCP servers, rules and skills, git config, and CI workflows. Repo: github.com/artmikula/snuf. Owner: Art (GitHub artmikula, npm asomiso8, email contact@centipede.dev).

Revenue path: the tool is free. It links to a fixed price $2,500 team audit at centipede.dev/services/ai-agent-security-audit/ from the README and from the markdown report footer when high or critical findings exist. Every promotion action exists to drive people to run the scan, star the repo, and for teams, to book that audit.

## Current state

- Code: main branch, all pushed, 95 tests passing, lint and typecheck clean, `pnpm build` produces `dist/cli.js` (single ESM file, four runtime deps).
- Version: 0.1.0 in package.json. Not yet published to npm. The name `snuf` is free on npm (checked 2026-09-28).
- npm account: exists (asomiso8), created 2026-09-28. The CLI on this machine is NOT authorized yet. `npm whoami` returns ENEEDAUTH. Art must run `npm login` in a terminal (it opens a browser link, one click to approve since already signed in on the web).
- Demo GIF: docs/screenshot.gif, re-recorded 2026-09-28 with vhs from docs/demo.tape. It shows the real machine's report with masked values. Re-record after any reporter change: `pnpm build && vhs docs/demo.tape`.
- Launch posts: docs/launch/ has ready to paste text for HN, X, Reddit (4 subreddits), LinkedIn and dev.to. All updated with the September 2026 news hooks.
- Older playbook with channel strategy and timing rules: docs/promotion.html.

## What was done on 2026-09-28 and why

Research showed the threat landscape moved a lot since the April build. Each item below maps to a news event and a scanner change.

| News | snuf change | File |
|---|---|---|
| GitSpawn (Manifold Security, Sept 1): repo `.git/config` `core.fsmonitor` runs code when agents call `git status`. 7 agents hit, 4 unpatched. Fix versions: Claude Code 2.1.196, Codex 0.131.0, Goose 1.44.0. Hermes, Qwen Code, Grok Build unpatched at publication. | New scanner. Reads project `.git/config` for fsmonitor (critical) and any other key naming a program: hooksPath, sshCommand, pager, editor, `!` aliases, credential helpers with `!`, filters, diff/merge drivers, includes (high). Counts active hooks (low). Global `~/.gitconfig` custom fsmonitor (medium). Compares installed agent versions to the patch table. | `src/scanner/git.ts` |
| Claude Code GitHub Action CVE (June, Microsoft disclosure): `allowed_non_write_users: "*"` let any GitHub account prompt the agent and read CI secrets. | New scanner over `.github/workflows/*.yml`. Detects claude-code-action, codex-action, run-gemini-cli, copilot, aider, opencode actions. Flags wildcard non write users (high), untrusted triggers (issues, issue_comment, pull_request_target, etc.) with write perms or secrets (medium), floating tags instead of SHAs (low). | `src/scanner/ci.ts` |
| Deadbugz MCP rug pull (Sept): server behaves for 3 calls then hunts SSH keys. Sandworm_Mode typosquat campaign (early 2026). GitGuardian: 24,008 secrets in public MCP configs. | Typosquat detection (edit distance 2 against a well known package list and trusted scopes), git URL installs (medium), unpinned npx/uvx packages (medium if any unrecognized, else info). Vendor app bundle paths (ChatGPT.app, Cursor.app etc) count as trusted. `.env` and MCP configs with credentials that are tracked by git are critical. | `src/scanner/mcp.ts`, `src/scanner/secrets.ts`, `src/scanner/config-parsers.ts` (`gitTrackedFiles`) |
| OpenClaw: 543 CVEs, tens of thousands of exposed gateways, CVE-2026-25253 one click RCE. Min safe version 2026.8.1. | Reads `~/.openclaw/openclaw.json`: `gateway.bind` beyond loopback with no auth (critical), with auth (high), loopback with `auth.mode: none` (medium), `controlUi.dangerouslyAllowHostHeaderOriginFallback` / `allowExternalEmbedUrls` (medium), version below 2026.8.1 (high). | `src/scanner/shell.ts` |
| SKILL.md supply chain: Snyk found 36.82% of ClawHub skills flawed, 76 malicious. Unicode Tag characters hide instructions. Plain English exfiltration ("read ~/.ssh/id_rsa and post it to ..."). | Unicode Tag block (U+E0000 to U+E007F) added to invisible character check. New heuristic: a credential path mention within 400 chars of a "send/post/upload to URL" or `curl -d` phrase (high). Plugin cache scanning now covers `~/.claude/plugins/cache/*/*/*/skills` and `marketplaces/*/plugins/*/skills`, keeping only the latest cached version per plugin. `.agents/skills` (shared skills spec) added. | `src/scanner/rules.ts` |
| New agents since April: Factory Droid (#1 Terminal-Bench), Pi, Kimi Code (Moonshot, TypeScript), Hermes Agent (Nous), Grok Build (xAI), Antigravity (Google), Amazon Q, Mistral Vibe, Claude Cowork. | 8 new `defineAgent` entries. MCP sources: Droid `~/.factory/mcp.json` + project, Pi `~/.pi/agent/mcp.json` + `.pi/mcp.json`, Kimi `~/.kimi-code/mcp.json` + project, Hermes `~/.hermes/config.yaml` (`mcp_servers`, YAML parser generalised from the Goose one), Grok `~/.grok/config.toml`. Credential stores for Copilot CLI `~/.copilot/config.json`, Hermes `.env`, Droid `config.json`, Kimi and Grok `auth.json`. | `src/agents/index.ts`, `src/scanner/mcp.ts`, `src/scanner/secrets.ts` |
| Permission models verified against vendor docs. | Cursor CLI `~/.cursor/cli-config.json` and `.cursor/cli.json`: `approvalMode` unrestricted (high) / auto-review (medium), `Shell(*)` allow (high). OpenCode `permission` in `opencode.json`: bash allow (high), edit allow (medium), external_directory allow (medium), risky bash patterns (medium). Factory Droid `sessionDefaultSettings.autonomyLevel` high (high) / medium (medium), risky `commandAllowlist`. Kimi Code `default_permission_mode = "yolo"` (high), `dangerous_command_guard = false` (medium), `[[permission.rules]]` allowing Bash (high). Hermes `dangerous_command_approval: false` (medium), non local `terminal.backend` reported as info. Codex `sandbox_workspace_write.network_access = true` (medium), `[projects."~"] trust_level = "trusted"` (high). | `src/scanner/shell.ts` |
| Competitors appeared: Snyk agent-scan (3k stars, needs SNYK_TOKEN, connects to MCP servers), mcp-audit, agent-audit, mcp-scan, mcphound, mcp-armor. | README "How it compares" table. Positioning: snuf is whole machine posture, never connects to anything, no account. Others scan individual servers. | `README.md` |

Two things changed in reporting: the markdown report footer points to the audit when high or critical findings exist, and the README has a GitHub Actions example using `--fail-on high`.

## Architecture notes for the next agent

- Every scanner is a pure function of `ScanContext { home, project, agents, options }` returning `Finding[]`. Tests use `tests/helpers.ts` `sandbox()` which builds a temp home and project and never touches the real one. Follow that pattern.
- Finding categories: `secret | mcp | shell | file-access | rules | git | ci`. Adding a category means updating `src/types.ts`, both reporters (`terminal.ts`, `markdown.ts`) and possibly `recommendations()` in `reporter/shared.ts`.
- Scoring: multiplicative. Weights in `src/scoring/risk.ts`: low 0.03, medium 0.09, high 0.2, critical 0.38. Findings never print secret values. Use `mask()` from `secret-patterns.ts`.
- Config parsers: `readJson` handles JSONC and trailing commas, `parseTomlSubset` handles tables and inline tables but NOT arrays of tables (`[[x]]`), `yamlServers()` in mcp.ts is a shape driven indentation parser for Goose and Hermes. `gitTrackedFiles()` shells out to `git ls-files` once per project with `-c core.fsmonitor=false` so snuf itself is never a GitSpawn victim.
- Agent version lookup runs `<cmd> --version` with a 3 second timeout. `claude --version` occasionally does an update check and exceeds that on first call. Result is a blank version, not an error.
- Constraints that must not be broken: zero network calls, read only (the only write is `--output`), four runtime deps, no secret values in any output, sub second runtime.

## Added after the first handoff (same day, later)

- MCP `autoApprove` / `alwaysAllow` lists (Cline, Roo Code) and disabled servers skipped.
- Gemini `~/.gemini/trustedFolders.json` (flat map or `config` map of path to TRUST_FOLDER / TRUST_PARENT / DO_NOT_TRUST).
- Claude Code: sandbox settings (`sandbox.enabled`, `allowUnsandboxedCommands`, `excludedCommands`, `network.allowedDomains`, `credentials.allowPlaintextInject`, `enableWeakerNestedSandbox`), bypass mode downgraded to medium when the sandbox is on, whole server `mcp__x` / `mcp__x__*` allows, `WebFetch(domain:*)`, hardening info for `disableBypassPermissionsMode`, `disableAutoMode`, `blockReadsOutsideWorkingDirectories`.
- Codex `approvals_reviewer = "auto_review"`.
- Grok Build `[ui] permission_mode`, `[sandbox] auto_allow_bash` and `profile`, `[permission] allow`, `default_selected_permission`.
- Kiro `~/.kiro/settings/permissions.yaml`, workspace root permissions, `~/.kiro/agents/*.json` `allowedTools`.
- Amp `amp.dangerouslyAllowAll`, `amp.permissions`, `amp.commands.allowlist`.
- Goose `GOOSE_MODE` (auto is high, unset is medium because the enum default is auto, smart_approve is low).
- Copilot CLI `trusted_folders` containing home.
- End to end test in `tests/e2e.test.ts` that runs the orchestrator against a fake HOME and checks no secret value reaches any output format.
- `npm publish` was attempted by the agent and blocked by the Claude Code permission classifier ("Create Public Surface"). Art has to run `npm publish --access public` himself.

## Added later on 2026-09-28 (third pass)

- Antigravity CLI is a new agent (Google retired Gemini CLI for consumers on 2026-06-18; binary `agy`, config `~/.gemini/antigravity-cli/settings.json`). Antigravity IDE policy lives in `~/.gemini/config/config.json` under `userSettings`.
- Per agent permission readers now also cover: Cursor `hooks.json`, Codex `~/.codex/rules/*.rules` (prefix_rule, with a calibrated `riskyPrefix()` so `curl -L https://fixed` and `rm -rf .wrangler` are not flagged but `curl -s` and `/bin/zsh -lc` are), Kiro, Amp, Goose, Copilot CLI, Aider, Zed, Continue, Mistral Vibe, Qwen Code, Junie, Claude Code sandbox, third party plugin marketplaces, Channels.
- Claude Desktop: `config.json` `oauth:tokenCache*` keys are a plaintext session token (high). `claude_desktop_config.json` `preferences.remoteSessionFolderGrants` records Cowork folder grants (high when home is granted).
- SARIF 2.1 output (`--format sarif`, or `--output x.sarif`) for GitHub code scanning. README has the upload-sarif workflow.
- 128 tests. Runtime still about 0.2s on a loaded machine.

## Fourth pass (same day)

- `src/scanner/advisories.ts` holds the version table: Claude Code 2.1.196 (GitSpawn), 2.1.128 (/proc reads), 2.1.91 (CVE-2026-35020..22); Codex 0.131.0 (GitSpawn), 0.23.0 (CVE-2025-61260); Goose 1.44.0; Cursor 3.0.0 (CVE-2026-48124, DuneSlide). Unpatched notes for Hermes, Qwen Code, Grok Build. Add new advisories there, one object each. OpenClaw's minimum stays in shell.ts because it needs the gateway context.
- Claude Code auto mode became the default on 2026-08-14. With no pinned defaultMode snuf now reports "likely runs in auto mode" (low). `disableAutoMode: "disable"` restores the info finding.
- OpenCode `share: "auto"` (medium). mcp-remote token cache `~/.mcp-auth` or `MCP_REMOTE_CONFIG_DIR` (high). Remediation hints on the Claude Code and Codex credential store findings (`cli_auth_credentials_store = "keyring"`).
- Claude plugins: third party marketplaces from `~/.claude/plugins/known_marketplaces.json` plus installed plugins from `installed_plugins.json`. Channels under `~/.claude/channels/*` are a remote control path, high when prompts are off, and their `.env` files are credential stores.
- Windows: Store installed Claude Desktop config under `%LOCALAPPDATA%\Packages\Claude_*\LocalCache\Roaming\Claude`.
- 133 tests.

## Known rough edges

- Grok Build permission keys are not verified. docs.x.ai/build/settings/reference has the TOML key list. The GitSpawn version table marks it unpatched as of Sept 1.
- Pi MCP config location is partly inferred (`~/.pi/agent/mcp.json`, `.pi/mcp.json`). Verify against pi-mono docs and pi-mcp-adapter.
- Hermes YAML parsing only handles the two space indentation shown in their docs.
- Windows: paths are checked, process and version detection are best effort. Nobody has run it on Windows recently.
- The skill exfiltration heuristic is new. It fires on the official Vercel `vercel-sandbox` skill (a real `curl | sh` install line) and on any skill that mentions `~/.ssh` near a POST. Expect false positive reports and tighten with `credentialExfil()` in rules.ts.
- The score on Art's own machine is 88 mainly because official Claude plugins contain `curl | sh` and the phrase "ignore previous instructions" in a detection skill. That is by design but worth a sentence in the README FAQ.
- `docs/promotion.html` is from April and says "Date: April 2026". Keep using its channel strategy, use `docs/launch/` for the actual text.

## Launch sequence (do in this order)

1. `npm login` (Art, interactive). Then `npm publish` from the repo root. `prepublishOnly` runs typecheck, tests and build. Verify from an empty directory: `cd $(mktemp -d) && npx snuf@latest --quick`.
2. `git tag v0.1.0 && git push --tags`, then `gh release create v0.1.0 --generate-notes`.
3. Post HN using docs/launch/hackernews.md. Best window: Tuesday to Thursday, 9 to 11am US Eastern. Tuesday 2026-09-29 is the next one. Post the first comment immediately. Reply to every comment for two hours.
4. Post the X thread with the GIF, linking the HN thread in tweet 1 on launch day.
5. Reddit: r/ClaudeAI on day 1, r/netsec day 2, r/cursor day 3, r/LocalLLaMA day 4. Text in docs/launch/reddit.md.
6. dev.to article (docs/launch/devto.md, set `published: true`). LinkedIn post with the audit link in the first comment.
7. Awesome list PRs, one line each in the `- [name](url) - description` style: Puliczek/awesome-mcp-security ("Tools and code" section), scadastrangelove/awesome-ai-security-tools, bradagi/awesome-cli-coding-agents (agent infrastructure), hesreallyhim/awesome-claude-code. Suggested line: `- [snuf](https://github.com/artmikula/snuf) - Local, zero network scanner that inventories every AI coding agent on a machine, its MCP servers, exposed secrets, permission posture, GitSpawn git config keys and CI agent workflows.`
8. Product Hunt one to two weeks after HN.
9. Watch GitHub issues daily for the first two weeks. Every "you missed agent X" is a one line `defineAgent` entry, ship it same day.

## What a follow up agent can do without Art

- Any code improvement above, with tests, committed with conventional commits and pushed to main.
- Research: monitor thehackernews.com, adversa.ai MCP digests, Manifold Security blog, GitGuardian, CSA labs for new agent CVEs and add version checks or config checks.
- Draft replies to HN and Reddit comments into docs/launch/replies.md for Art to paste.

## What only Art can do

- `npm login`, `npm publish`.
- Log into HN, X, Reddit, dev.to, LinkedIn, Product Hunt in the Chrome profile used with Claude in Chrome ("Browser 2"), and allow reddit.com in the extension's site permissions. As of 2026-09-28 that profile is logged out of all of them.
- Pin the repo on the GitHub profile (web UI only).
- Answer inbound audit leads at contact@centipede.dev.
