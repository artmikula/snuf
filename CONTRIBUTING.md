# Contributing

Thanks for looking. The most useful contributions are agent coverage and false positive reports.

## Setup

```bash
pnpm install
pnpm test
pnpm build && node dist/cli.js
```

`pnpm typecheck` and `pnpm lint` run in CI on Linux and macOS with Node 20 and 22.

## Adding an agent

1. Add a `defineAgent` entry in `src/agents/index.ts` with the config paths the tool really uses. Check the vendor docs, not memory.
2. Add it to `ALL_AGENTS` and `AGENT_SLUGS`.
3. If it loads MCP servers, add its config file to `mcpConfigSources` in `src/scanner/mcp.ts`. Reuse `jsonKey('mcpServers')` where the format is standard.
4. If it has a permission or approval setting on disk, add a case in `src/scanner/shell.ts`.
5. Add a test under `tests/` using the sandbox helper. Tests write to a temp directory and never touch your real home.

## Rules

- Zero network calls. A PR that adds `fetch`, `http`, or a telemetry dependency will be closed.
- Read only. The only write is `--output`.
- Never print a secret value. Use `mask()` from `src/scanner/secret-patterns.ts`.
- Keep the dependency list as it is. Four runtime deps is the budget.
- No semicolons, two spaces, single quotes. Prettier config is in the repo.

## Reporting a false positive

Open an issue with the finding title and the config that triggered it, with values replaced. Say which agent and OS. If snuf missed something on your machine, that is a bug too.
