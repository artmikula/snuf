import type { ScanResult, ScanOptions, Finding, Severity } from '../types.js'
import { visibleFindings } from './shared.js'

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
}

const RANK: Record<Severity, number> = { critical: 9.5, high: 8, medium: 5, low: 2.5, info: 0 }

function ruleId(f: Finding): string {
  const slug = f.title
    .toLowerCase()
    .replace(/\d+/g, 'n')
    .replace(/[^a-z]+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 60)
  return `snuf/${f.category}/${slug}`
}

export function renderSarif(result: ScanResult, options: ScanOptions): string {
  const findings = visibleFindings(result, options.severity)
  const rules = new Map<string, { id: string; name: string; shortDescription: { text: string }; defaultConfiguration: { level: string }; properties: { category: string; 'security-severity': string } }>()
  const results = findings.map((f) => {
    const id = ruleId(f)
    if (!rules.has(id)) {
      rules.set(id, {
        id,
        name: f.title,
        shortDescription: { text: f.title },
        defaultConfiguration: { level: LEVEL[f.severity] },
        properties: { category: f.category, 'security-severity': String(RANK[f.severity]) },
      })
    }
    return {
      ruleId: id,
      level: LEVEL[f.severity],
      message: { text: `${f.title}. ${f.detail}` },
      ...(f.path
        ? { locations: [{ physicalLocation: { artifactLocation: { uri: f.path.startsWith('/') ? `file://${f.path}` : f.path } } }] }
        : {}),
      properties: { severity: f.severity, category: f.category, ...(f.agent ? { agent: f.agent } : {}) },
    }
  })
  return JSON.stringify(
    {
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'snuf',
              version: result.version,
              informationUri: 'https://github.com/artmikula/snuf',
              rules: [...rules.values()],
            },
          },
          invocations: [{ executionSuccessful: true, endTimeUtc: result.scannedAt }],
          properties: { score: result.score, projectDir: result.projectDir, platform: result.platform },
          results,
        },
      ],
    },
    null,
    2
  )
}
