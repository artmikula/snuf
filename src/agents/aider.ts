import { existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent } from '../types.js'

function getConfigPaths(): string[] {
  const home = homedir()
  return [
    join(home, '.aider.conf.yml'),
    join(process.cwd(), '.aider.conf.yml'),
  ]
}

function getVersion(): string | undefined {
  try {
    const out = execSync('aider --version 2>/dev/null', { timeout: 500, stdio: 'pipe' })
    return out.toString().trim().split(/\s+/).at(-1)
  } catch {
    return undefined
  }
}

function isRunning(): boolean {
  try {
    execSync('pgrep -f aider', { timeout: 500, stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

export async function detectAgent(): Promise<Agent | null> {
  const configPaths = getConfigPaths().filter((p) => existsSync(p))
  if (configPaths.length === 0) return null

  return {
    name: 'Aider',
    slug: 'aider',
    version: getVersion(),
    running: isRunning(),
    configPaths,
  }
}
