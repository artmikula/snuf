import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent, McpServer, Finding } from '../types.js'

const SECRET_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /ANTHROPIC_API_KEY/i, label: 'Anthropic API key' },
  { pattern: /OPENAI_API_KEY/i, label: 'OpenAI API key' },
  { pattern: /OPENAI_ORG/i, label: 'OpenAI org ID' },
  { pattern: /GITHUB_TOKEN/i, label: 'GitHub token' },
  { pattern: /GH_TOKEN/i, label: 'GitHub token' },
  { pattern: /AWS_ACCESS_KEY_ID/i, label: 'AWS access key' },
  { pattern: /AWS_SECRET_ACCESS_KEY/i, label: 'AWS secret key' },
  { pattern: /AWS_SESSION_TOKEN/i, label: 'AWS session token' },
  { pattern: /GOOGLE_API_KEY/i, label: 'Google API key' },
  { pattern: /GCLOUD_SERVICE_KEY/i, label: 'GCloud service key' },
  { pattern: /DATABASE_URL/i, label: 'Database URL' },
  { pattern: /POSTGRES_URL/i, label: 'Postgres URL' },
  { pattern: /MYSQL_URL/i, label: 'MySQL URL' },
  { pattern: /MONGODB_URI/i, label: 'MongoDB URI' },
  { pattern: /REDIS_URL/i, label: 'Redis URL' },
  { pattern: /STRIPE_SECRET_KEY/i, label: 'Stripe secret key' },
  { pattern: /STRIPE_API_KEY/i, label: 'Stripe API key' },
  { pattern: /SLACK_TOKEN/i, label: 'Slack token' },
  { pattern: /SLACK_BOT_TOKEN/i, label: 'Slack bot token' },
  { pattern: /DISCORD_TOKEN/i, label: 'Discord token' },
  { pattern: /HUGGINGFACE_TOKEN/i, label: 'HuggingFace token' },
  { pattern: /HF_TOKEN/i, label: 'HuggingFace token' },
  { pattern: /REPLICATE_API_KEY/i, label: 'Replicate API key' },
  { pattern: /GROQ_API_KEY/i, label: 'Groq API key' },
  { pattern: /MISTRAL_API_KEY/i, label: 'Mistral API key' },
  { pattern: /COHERE_API_KEY/i, label: 'Cohere API key' },
  { pattern: /TOGETHER_API_KEY/i, label: 'Together API key' },
  { pattern: /NPM_TOKEN/i, label: 'npm token' },
  { pattern: /PYPI_TOKEN/i, label: 'PyPI token' },
  { pattern: /DOCKER_PASSWORD/i, label: 'Docker password' },
  { pattern: /SECRET_KEY/i, label: 'Secret key' },
  { pattern: /API_SECRET/i, label: 'API secret' },
  { pattern: /PRIVATE_KEY/i, label: 'Private key' },
  { pattern: /ENCRYPTION_KEY/i, label: 'Encryption key' },
]

function matchSecretKey(key: string): string | undefined {
  for (const { pattern, label } of SECRET_PATTERNS) {
    if (pattern.test(key)) return label
  }
  return undefined
}

function parseEnvFile(filePath: string): Record<string, string> {
  const result: Record<string, string> = {}
  try {
    const content = readFileSync(filePath, 'utf-8')
    for (const line of content.split('\n')) {
      const trimmed = line.trim()
      if (!trimmed || trimmed.startsWith('#')) continue
      const eq = trimmed.indexOf('=')
      if (eq === -1) continue
      const key = trimmed.slice(0, eq).trim()
      result[key] = trimmed.slice(eq + 1).trim()
    }
  } catch {
    // unreadable — skip
  }
  return result
}

export async function scanSecrets(
  agents: Agent[],
  mcpServers: McpServer[]
): Promise<Finding[]> {
  const findings: Finding[] = []
  const home = homedir()

  // 1. Scan MCP server env vars
  for (const server of mcpServers) {
    if (!server.envVars) continue
    for (const [key] of Object.entries(server.envVars)) {
      const label = matchSecretKey(key)
      if (label) {
        findings.push({
          category: 'secret',
          severity: 'critical',
          title: `${label} exposed in MCP config`,
          detail: `${key} is set in MCP server "${server.name}" (${server.source})`,
          agent: server.source,
        })
      }
    }
  }

  // 2. Scan process.env for secrets inherited by all agents
  if (agents.length > 0) {
    for (const [key] of Object.entries(process.env)) {
      const label = matchSecretKey(key)
      if (label) {
        findings.push({
          category: 'secret',
          severity: 'high',
          title: `${label} in environment (inherited by all agents)`,
          detail: `${key} is set in the shell environment and inherited by every AI agent process`,
        })
      }
    }
  }

  // 3. Scan .env files in agent config directories and common project locations
  const envLocations: Array<[string, string]> = [
    [join(home, '.env'), 'home directory'],
    [join(process.cwd(), '.env'), 'project root'],
    [join(process.cwd(), '.env.local'), 'project root'],
    [join(process.cwd(), '.env.development'), 'project root'],
    [join(process.cwd(), '.env.production'), 'project root'],
  ]

  for (const [filePath, location] of envLocations) {
    if (!existsSync(filePath)) continue
    const vars = parseEnvFile(filePath)
    for (const key of Object.keys(vars)) {
      const label = matchSecretKey(key)
      if (label) {
        findings.push({
          category: 'secret',
          severity: 'high',
          title: `${label} in .env file`,
          detail: `${key} found in .env file at ${location} (${filePath})`,
          path: filePath,
        })
      }
    }
  }

  return findings
}
