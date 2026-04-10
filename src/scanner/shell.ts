import type { Agent, Finding } from '../types.js'

export async function scanShell(_agents: Agent[]): Promise<Finding[]> {
  // TODO: detect shell execution permission model per agent
  return []
}
