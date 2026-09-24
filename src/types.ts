export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export const SEVERITIES: Severity[] = ['info', 'low', 'medium', 'high', 'critical']

export type OutputFormat = 'terminal' | 'json' | 'markdown'

export interface Agent {
  name: string
  slug: string
  version?: string
  running: boolean
  configPaths: string[]
}

export interface McpServer {
  name: string
  agent: string
  transport: 'stdio' | 'http' | 'unknown'
  command?: string
  args?: string[]
  url?: string
  envVars?: Record<string, string>
  headers?: Record<string, string>
  secretKeys: string[]
  hasNetworkAccess: boolean
  hasShellAccess: boolean
  isKnown: boolean
  source: string
}

export type FindingCategory = 'agent' | 'mcp' | 'secret' | 'file-access' | 'shell' | 'rules'

export interface Finding {
  category: FindingCategory
  severity: Severity
  title: string
  detail: string
  path?: string
  agent?: string
}

export interface ScanResult {
  version: string
  agents: Agent[]
  mcpServers: McpServer[]
  findings: Finding[]
  score: number
  scannedAt: string
  platform: string
  projectDir: string
}

export interface ScanOptions {
  format?: OutputFormat
  output?: string
  agent?: string
  severity?: Severity
  quick?: boolean
  project?: string
  failOn?: Severity
}

export interface ScanContext {
  home: string
  project: string
  agents: Agent[]
  options: ScanOptions
}
