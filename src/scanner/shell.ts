import { existsSync, readFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { join } from 'node:path'
import type { Agent, Finding } from '../types.js'

interface ShellConfig {
  autoApprove?: boolean
  allowedCommands?: string[]
  deniedCommands?: string[]
}

function readJsonFile(path: string): unknown {
  try {
    return JSON.parse(readFileSync(path, 'utf-8'))
  } catch {
    return null
  }
}

function detectClaudeCodeShellConfig(home: string): ShellConfig {
  // Claude Code settings live in ~/.claude/settings.json or ~/.claude.json
  const settingsPath = join(home, '.claude', 'settings.json')
  const claudeJsonPath = join(home, '.claude.json')

  let raw: unknown = null
  if (existsSync(settingsPath)) {
    raw = readJsonFile(settingsPath)
  } else if (existsSync(claudeJsonPath)) {
    raw = readJsonFile(claudeJsonPath)
  }

  if (!raw || typeof raw !== 'object') return {}

  const settings = raw as Record<string, unknown>

  // Check for auto-approve patterns in Claude Code config
  const autoApprove =
    settings['autoApproveMode'] === true ||
    settings['autoApprove'] === true ||
    settings['permissions'] === 'auto'

  return { autoApprove }
}

function detectCursorShellConfig(): ShellConfig {
  // Cursor doesn't expose a shell permission model in config files
  // but it does execute commands via MCP and terminal
  return { autoApprove: false }
}

export async function scanShell(agents: Agent[]): Promise<Finding[]> {
  const findings: Finding[] = []
  const home = homedir()

  for (const agent of agents) {
    switch (agent.slug) {
      case 'claude-code': {
        const config = detectClaudeCodeShellConfig(home)

        if (config.autoApprove) {
          findings.push({
            category: 'shell',
            severity: 'high',
            title: 'Claude Code is in auto-approve mode',
            detail:
              'Shell commands are executed without confirmation prompts — any instruction can run arbitrary commands',
            agent: agent.slug,
          })
        } else {
          // Claude Code has shell access by default (it's a coding agent)
          findings.push({
            category: 'shell',
            severity: 'info',
            title: 'Claude Code has shell execution capability',
            detail:
              'Claude Code can run shell commands. Permission prompts are active (default behavior)',
            agent: agent.slug,
          })
        }
        break
      }

      case 'cursor':
      case 'windsurf':
      case 'copilot': {
        // These agents have integrated terminals but require user interaction
        findings.push({
          category: 'shell',
          severity: 'low',
          title: `${agent.name} has integrated terminal access`,
          detail: `${agent.name} can suggest and execute terminal commands. User approval typically required`,
          agent: agent.slug,
        })
        break
      }

      case 'aider': {
        // Aider can auto-run linting/test commands
        findings.push({
          category: 'shell',
          severity: 'medium',
          title: 'Aider can auto-run commands',
          detail:
            'Aider can automatically run linting, tests, and build commands as part of its edit loop',
          agent: agent.slug,
        })
        break
      }

      case 'codex': {
        // OpenAI Codex CLI runs in a sandbox by default but can break out
        findings.push({
          category: 'shell',
          severity: 'low',
          title: 'Codex CLI has sandboxed shell access',
          detail:
            'Codex CLI runs commands in a sandbox environment by default. Approve mode controls access level',
          agent: agent.slug,
        })
        break
      }

      case 'gemini-cli': {
        findings.push({
          category: 'shell',
          severity: 'info',
          title: 'Gemini CLI has shell execution capability',
          detail:
            'Gemini CLI can run shell commands with user confirmation (default behavior)',
          agent: agent.slug,
        })
        break
      }

      default: {
        findings.push({
          category: 'shell',
          severity: 'low',
          title: `${agent.name} may have shell access`,
          detail: `${agent.name} is installed — verify its shell execution permission model`,
          agent: agent.slug,
        })
        break
      }
    }
  }

  return findings
}
