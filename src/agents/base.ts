import { existsSync } from 'node:fs'
import { execSync } from 'node:child_process'
import type { Agent } from '../types.js'

export interface AgentSpec {
  name: string
  slug: string
  paths: (home: string, project: string) => string[]
  versionCommand?: string
  processNames?: string[]
  desktopApp?: boolean
}

function run(command: string, timeout = 1500): string | undefined {
  try {
    return execSync(command, { timeout, stdio: ['ignore', 'pipe', 'ignore'] }).toString()
  } catch {
    return undefined
  }
}

export function parseVersion(output: string | undefined): string | undefined {
  if (!output) return undefined
  const firstLine = output.trim().split('\n')[0] ?? ''
  const match = firstLine.match(/\d+\.\d+(\.\d+)?([-.][\w.]+)?/)
  return match?.[0]
}

let processTable: Array<{ comm: string; args: string }> | undefined

function processes(): Array<{ comm: string; args: string }> {
  if (processTable) return processTable
  processTable = []
  if (process.platform === 'win32') {
    const out = run('tasklist /FO CSV /NH')
    for (const line of out?.split('\n') ?? []) {
      const name = line.split(',')[0]?.replace(/"/g, '').trim()
      if (name) processTable.push({ comm: name.replace(/\.exe$/i, ''), args: name })
    }
    return processTable
  }
  const out = run('ps -axo comm=,args=')
  for (const line of out?.split('\n') ?? []) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const [comm, ...rest] = trimmed.split(/\s+/)
    processTable.push({ comm: comm?.split('/').at(-1) ?? '', args: rest.join(' ') })
  }
  return processTable
}

export function isProcessRunning(names: string[], desktopApp = false): boolean {
  const table = processes()
  return names.some((name) =>
    table.some((proc) => {
      if (proc.comm !== name) return false
      if (desktopApp) return true
      return !proc.args.includes('.app/') && !proc.comm.includes('.app/')
    })
  )
}

export function defineAgent(spec: AgentSpec) {
  return async function detectAgent(home: string, project: string): Promise<Agent | null> {
    const configPaths = spec.paths(home, project).filter((p) => existsSync(p))
    if (configPaths.length === 0) return null

    const version = spec.versionCommand
      ? parseVersion(run(`${spec.versionCommand} --version`))
      : undefined
    const running = spec.processNames
      ? isProcessRunning(spec.processNames, spec.desktopApp)
      : false

    return { name: spec.name, slug: spec.slug, version, running, configPaths }
  }
}
