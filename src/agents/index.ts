import { join } from 'node:path'
import { defineAgent } from './base.js'

const appSupport = (home: string) =>
  process.platform === 'darwin'
    ? join(home, 'Library', 'Application Support')
    : process.platform === 'win32'
      ? (process.env['APPDATA'] ?? join(home, 'AppData', 'Roaming'))
      : join(home, '.config')

const vscodeGlobalStorage = (home: string) =>
  process.platform === 'linux'
    ? join(home, '.config', 'Code', 'User', 'globalStorage')
    : join(appSupport(home), 'Code', 'User', 'globalStorage')

export const claudeCode = defineAgent({
  name: 'Claude Code',
  slug: 'claude-code',
  paths: (home, project) => [
    join(home, '.claude'),
    join(home, '.claude.json'),
    join(project, '.claude'),
    join(project, 'CLAUDE.md'),
  ],
  versionCommand: 'claude',
  processNames: ['claude'],
})

export const claudeDesktop = defineAgent({
  name: 'Claude Desktop',
  slug: 'claude-desktop',
  paths: (home) => [
    join(appSupport(home), 'Claude', 'claude_desktop_config.json'),
    join(home, '.config', 'Claude', 'claude_desktop_config.json'),
  ],
  processNames: ['Claude'],
  desktopApp: true,
})

export const cursor = defineAgent({
  name: 'Cursor',
  slug: 'cursor',
  paths: (home, project) => [
    join(home, '.cursor'),
    join(project, '.cursor'),
    join(project, '.cursorrules'),
  ],
  versionCommand: 'cursor',
  processNames: ['Cursor', 'cursor-agent'],
  desktopApp: true,
})

export const copilot = defineAgent({
  name: 'GitHub Copilot',
  slug: 'copilot',
  paths: (home, project) => [
    join(home, '.copilot'),
    join(home, '.config', 'github-copilot'),
    join(project, '.github', 'copilot-instructions.md'),
  ],
  versionCommand: 'copilot',
  processNames: ['copilot'],
})

export const windsurf = defineAgent({
  name: 'Windsurf',
  slug: 'windsurf',
  paths: (home, project) => [
    join(home, '.codeium', 'windsurf'),
    join(home, '.windsurf'),
    join(project, '.windsurf'),
    join(project, '.windsurfrules'),
  ],
  versionCommand: 'windsurf',
  processNames: ['Windsurf'],
  desktopApp: true,
})

export const aider = defineAgent({
  name: 'Aider',
  slug: 'aider',
  paths: (home, project) => [
    join(home, '.aider.conf.yml'),
    join(home, '.aider'),
    join(project, '.aider.conf.yml'),
    join(project, '.aider.chat.history.md'),
  ],
  versionCommand: 'aider',
  processNames: ['aider'],
})

export const codex = defineAgent({
  name: 'Codex CLI',
  slug: 'codex',
  paths: (home) => [join(home, '.codex')],
  versionCommand: 'codex',
  processNames: ['codex'],
})

export const geminiCli = defineAgent({
  name: 'Gemini CLI',
  slug: 'gemini-cli',
  paths: (home, project) => [join(home, '.gemini'), join(project, 'GEMINI.md')],
  versionCommand: 'gemini',
  processNames: ['gemini'],
})

export const openclaw = defineAgent({
  name: 'OpenClaw',
  slug: 'openclaw',
  paths: (home) => [join(home, '.openclaw'), join(home, '.config', 'openclaw')],
  versionCommand: 'openclaw',
  processNames: ['openclaw'],
})

export const opencode = defineAgent({
  name: 'OpenCode',
  slug: 'opencode',
  paths: (home, project) => [
    join(home, '.config', 'opencode'),
    join(home, '.opencode'),
    join(project, 'opencode.json'),
    join(project, '.opencode'),
  ],
  versionCommand: 'opencode',
  processNames: ['opencode'],
})

export const cline = defineAgent({
  name: 'Cline',
  slug: 'cline',
  paths: (home, project) => [
    join(vscodeGlobalStorage(home), 'saoudrizwan.claude-dev'),
    join(project, '.clinerules'),
  ],
})

export const rooCode = defineAgent({
  name: 'Roo Code',
  slug: 'roo-code',
  paths: (home, project) => [
    join(vscodeGlobalStorage(home), 'rooveterinaryinc.roo-cline'),
    join(project, '.roo'),
    join(project, '.roomodes'),
  ],
})

export const kiro = defineAgent({
  name: 'Kiro',
  slug: 'kiro',
  paths: (home, project) => [join(home, '.kiro'), join(project, '.kiro')],
  processNames: ['Kiro'],
  desktopApp: true,
})

export const amp = defineAgent({
  name: 'Amp',
  slug: 'amp',
  paths: (home) => [join(home, '.config', 'amp'), join(home, '.amp')],
  versionCommand: 'amp',
  processNames: ['amp'],
})

export const zed = defineAgent({
  name: 'Zed',
  slug: 'zed',
  paths: (home) => [join(home, '.config', 'zed', 'settings.json')],
  processNames: ['zed', 'Zed'],
  desktopApp: true,
})

export const continueDev = defineAgent({
  name: 'Continue',
  slug: 'continue',
  paths: (home, project) => [join(home, '.continue'), join(project, '.continue')],
})

export const goose = defineAgent({
  name: 'Goose',
  slug: 'goose',
  paths: (home) => [join(home, '.config', 'goose')],
  versionCommand: 'goose',
  processNames: ['goose'],
})

export const trae = defineAgent({
  name: 'Trae',
  slug: 'trae',
  paths: (home, project) => [join(home, '.trae'), join(project, '.trae')],
  processNames: ['Trae'],
  desktopApp: true,
})

export const qwenCode = defineAgent({
  name: 'Qwen Code',
  slug: 'qwen-code',
  paths: (home) => [join(home, '.qwen')],
  versionCommand: 'qwen',
  processNames: ['qwen'],
})

export const junie = defineAgent({
  name: 'JetBrains Junie',
  slug: 'junie',
  paths: (home, project) => [join(home, '.junie'), join(project, '.junie')],
})

export const ALL_AGENTS = [
  claudeCode,
  claudeDesktop,
  cursor,
  copilot,
  windsurf,
  codex,
  geminiCli,
  aider,
  opencode,
  openclaw,
  cline,
  rooCode,
  kiro,
  amp,
  zed,
  continueDev,
  goose,
  trae,
  qwenCode,
  junie,
]

export const AGENT_SLUGS = [
  'claude-code',
  'claude-desktop',
  'cursor',
  'copilot',
  'windsurf',
  'codex',
  'gemini-cli',
  'aider',
  'opencode',
  'openclaw',
  'cline',
  'roo-code',
  'kiro',
  'amp',
  'zed',
  'continue',
  'goose',
  'trae',
  'qwen-code',
  'junie',
]
