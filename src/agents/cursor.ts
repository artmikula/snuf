import { existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent } from '../types.js'

function getConfigPaths(): string[] {
  const home = homedir()
  return [
    join(home, '.cursor'),
    join(process.cwd(), '.cursor'),
  ]
}

function getVersion(): string | undefined {
  try {
    const out = execSync('cursor --version 2>/dev/null', { timeout: 500, stdio: 'pipe' })
    return out.toString().trim().split(/\s+/).at(-1)
  } catch {
    return undefined
  }
}

function isRunning(): boolean {
  try {
    execSync('pgrep -f Cursor', { timeout: 500, stdio: 'pipe' })
    return true
  } catch {
    return false
  }
}

export async function detectAgent(): Promise<Agent | null> {
  const configPaths = getConfigPaths().filter((p) => existsSync(p))
  if (configPaths.length === 0) return null

  return {
    name: 'Cursor',
    slug: 'cursor',
    version: getVersion(),
    running: isRunning(),
    configPaths,
  }
}
