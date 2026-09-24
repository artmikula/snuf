import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import type { ScanContext, ScanOptions, Agent } from '../src/types.js'

export interface Sandbox {
  home: string
  project: string
  write: (relative: string, content: string) => string
  ctx: (agents?: Agent[], options?: ScanOptions) => ScanContext
  cleanup: () => void
}

export function sandbox(): Sandbox {
  const root = mkdtempSync(join(tmpdir(), 'snuf-'))
  const home = join(root, 'home')
  const project = join(home, 'work', 'app')
  mkdirSync(project, { recursive: true })
  return {
    home,
    project,
    write(relative, content) {
      const path = join(root, relative)
      mkdirSync(dirname(path), { recursive: true })
      writeFileSync(path, content)
      return path
    },
    ctx(agents = [], options = {}) {
      return { home, project, agents, options }
    },
    cleanup() {
      rmSync(root, { recursive: true, force: true })
    },
  }
}

export function agent(slug: string, name = slug): Agent {
  return { slug, name, running: false, configPaths: [] }
}
