import { existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent } from '../types.js'

function getConfigPaths(): string[] {
  const home = homedir()
  return [
    join(home, '.openclaw'),
  ]
}

function isRunning(): boolean {
  try {
    execSync('pgrep -f openclaw', { timeout: 500, stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

export async function detectAgent(): Promise<Agent | null> {
  const configPaths = getConfigPaths().filter((p) => existsSync(p))
  if (configPaths.length === 0) return null

  return {
    name: 'OpenClaw',
    slug: 'openclaw',
    running: isRunning(),
    configPaths,
  }
}
