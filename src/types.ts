export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface Agent {
  name: string
  slug: string
  version?: string
  running: boolean
  configPaths: string[]
  installPath?: string
}

export interface McpServer {
  name: string
  transport: 'stdio' | 'http' | 'unknown'
  command?: string
  args?: string[]
  envVars?: Record<string, string>
  hasNetworkAccess: boolean
  hasShellAccess: boolean
  isKnown: boolean
  source: string
}

export interface Finding {
  category: 'agent' | 'mcp' | 'secret' | 'file-access' | 'shell' | 'skill'
  severity: Severity
  title: string
  detail: string
  path?: string
  agent?: string
}

export interface ScanResult {
  agents: Agent[]
  mcpServers: McpServer[]
  findings: Finding[]
  score: number
  scannedAt: string
  platform: string
}

export interface ScanOptions {
  format?: string
  output?: string
  agent?: string
  severity?: string
  quick?: boolean
  project?: string
}
