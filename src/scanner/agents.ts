import type { Agent, ScanOptions } from '../types.js'
import { ALL_AGENTS } from '../agents/index.js'

export async function detectAgents(
  home: string,
  project: string,
  options: ScanOptions
): Promise<Agent[]> {
  const results = await Promise.all(ALL_AGENTS.map((detect) => detect(home, project)))
  const agents = results.filter((a): a is Agent => a !== null)
  if (options.agent) return agents.filter((a) => a.slug === options.agent)
  return agents
}
