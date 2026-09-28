# X thread

Attach docs/screenshot.gif to tweet 2.

1/
Last month a repo's .git/config could run code in Claude Code, Codex, Cursor and 4 other agents the moment they ran git status. Before any prompt. Outside any sandbox.

I wrote one command that shows what the AI agents on your machine can actually reach.

npx snuf

2/
Here's what it found on my own laptop:

🔴 API key sitting in an MCP config I forgot about
🔴 Claude Code once started from ~ so every credential on disk was "in scope"
⚠️ 37 pre approved shell patterns, two of them reach the network

Score 76/100. Not great.

3/
It checks 28 agents. Claude Code, Cursor, Codex, Copilot, Gemini CLI, OpenClaw, Goose, Droid, Pi, Kimi, Hermes, Grok Build, and more.

For each: version, running or not, permission mode, every MCP server it loads, and what it can reach.

4/
The September specific stuff:

• GitSpawn: .git/config keys that name a program, plus whether your agent version is patched
• Deadbugz: MCP servers pinned to nothing, so a rug pull reaches you same day
• Typosquats one letter off a known MCP package
• CI workflows where any GitHub account can prompt your agent

5/
It never phones home. No network calls, no account, no AI model. It reads config files and prints. Values are masked in every format including JSON.

Under a second. MIT.

6/
github.com/artmikula/snuf

Run it and reply with your score. I want to know which findings are most common.
