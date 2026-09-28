# LinkedIn

Two of my clients asked the same question this month: "what can the AI coding tools on our developers' laptops actually access?"

Nobody had an answer. So I built the tool that gives one.

snuf is a free, open source command. Each developer runs:

npx snuf --format json --output snuf.json

It inventories every AI agent on the machine (Claude Code, Cursor, Copilot, Codex, Gemini CLI and 23 more), every MCP server they load, credentials sitting in config files, permission modes that skip prompts, and the sensitive paths in reach. It also checks the two attacks that made September's headlines: GitSpawn (a cloned repo's git config running code through the agent) and unpinned MCP packages that a rug pull reaches the same day.

No network calls. Read only. Secret values are masked in every output.

For teams that want the review done for them, Centipede Software does a fixed price audit built on the scan: every machine, every config, a written fix list ordered by impact, delivered in five business days. Link in the comments.

github.com/artmikula/snuf
