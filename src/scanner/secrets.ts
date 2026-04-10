import type { Agent, McpServer, Finding } from '../types.js'

export async function scanSecrets(
  _agents: Agent[],
  _mcpServers: McpServer[]
): Promise<Finding[]> {
  // TODO: scan API keys in MCP configs, env vars, and .env files
  return []
}
