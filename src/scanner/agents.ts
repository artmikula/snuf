import type { Agent, ScanOptions } from '../types.js'
import { detectAgent as detectClaudeCode } from '../agents/claude-code.js'
import { detectAgent as detectCursor } from '../agents/cursor.js'
import { detectAgent as detectCopilot } from '../agents/copilot.js'
import { detectAgent as detectWindsurf } from '../agents/windsurf.js'
import { detectAgent as detectAider } from '../agents/aider.js'
import { detectAgent as detectCodex } from '../agents/codex.js'
import { detectAgent as detectOpenclaw } from '../agents/openclaw.js'
import { detectAgent as detectOpencode } from '../agents/opencode.js'
import { detectAgent as detectGemini } from '../agents/gemini-cli.js'

const ALL_ADAPTERS = [
  detectClaudeCode,
  detectCursor,
  detectCopilot,
  detectWindsurf,
  detectAider,
  detectCodex,
  detectOpenclaw,
  detectOpencode,
  detectGemini,
]

export async function detectAgents(options: ScanOptions): Promise<Agent[]> {
  const results = await Promise.all(ALL_ADAPTERS.map((fn) => fn()))
  const agents = results.filter((a): a is Agent => a !== null)

  if (options.agent) {
    return agents.filter((a) => a.slug === options.agent)
  }

  return agents
}
