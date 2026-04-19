import { existsSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent, Finding } from '../types.js'

interface SensitiveDir {
  path: string
  label: string
  severity: 'high' | 'critical'
  detail: string
}

function getSensitiveDirs(home: string): SensitiveDir[] {
  return [
    {
      path: join(home, '.ssh'),
      label: 'SSH keys',
      severity: 'critical',
      detail: 'SSH private keys could be used to access servers and repositories',
    },
    {
      path: join(home, '.aws'),
      label: 'AWS credentials',
      severity: 'critical',
      detail: 'AWS credentials could grant access to cloud infrastructure',
    },
    {
      path: join(home, '.config', 'gcloud'),
      label: 'GCloud credentials',
      severity: 'critical',
      detail: 'GCloud credentials could grant access to Google Cloud resources',
    },
    {
      path: join(home, '.kube'),
      label: 'Kubernetes config',
      severity: 'high',
      detail: 'Kubernetes config contains cluster credentials and contexts',
    },
    {
      path: join(home, '.gnupg'),
      label: 'GPG keys',
      severity: 'high',
      detail: 'GPG private keys could be used to sign or decrypt data',
    },
    {
      path: join(home, '.docker', 'config.json'),
      label: 'Docker registry credentials',
      severity: 'high',
      detail: 'Docker config contains registry authentication tokens',
    },
    {
      path: join(home, '.config', 'gh', 'hosts.yml'),
      label: 'GitHub CLI token',
      severity: 'high',
      detail: 'GitHub CLI stores OAuth tokens with broad repository access',
    },
    {
      path: join(home, '.netrc'),
      label: '.netrc credentials',
      severity: 'high',
      detail: '.netrc stores plaintext credentials for network services',
    },
  ]
}

export async function scanPermissions(agents: Agent[]): Promise<Finding[]> {
  if (agents.length === 0) return []

  const findings: Finding[] = []
  const home = homedir()
  const sensitiveDirs = getSensitiveDirs(home)
  const agentNames = agents.map((a) => a.name).join(', ')

  // Check if any agent has broad home-directory access
  // Claude Code and most agents run from the home dir by default
  const homeAccessAgents = agents.filter((a) =>
    a.configPaths.some((p) => p.startsWith(home))
  )

  if (homeAccessAgents.length > 0) {
    findings.push({
      category: 'file-access',
      severity: 'high',
      title: 'AI agents have access to home directory',
      detail: `${homeAccessAgents.map((a) => a.name).join(', ')} ${homeAccessAgents.length === 1 ? 'has' : 'have'} config in ~ and can read files across your home directory`,
    })
  }

  // Check each sensitive directory
  for (const { path, label, severity, detail } of sensitiveDirs) {
    if (!existsSync(path)) continue
    findings.push({
      category: 'file-access',
      severity,
      title: `${label} accessible by AI agents`,
      detail: `${path} exists and is readable by ${agentNames}`,
      path,
    })
  }

  return findings
}
