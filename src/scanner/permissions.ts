import type { Agent, Finding } from '../types.js'

export async function scanPermissions(_agents: Agent[]): Promise<Finding[]> {
  // TODO: check agent access to ~/.ssh, ~/.aws, home directory
  return []
}
