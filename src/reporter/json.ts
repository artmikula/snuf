import type { ScanResult, ScanOptions } from '../types.js'
import { scoreBand } from '../scoring/risk.js'
import { visibleFindings, countBySeverity, recommendations } from './shared.js'

export function renderJson(result: ScanResult, options: ScanOptions): string {
  const findings = visibleFindings(result, options.severity)
  if (options.quick) {
    return JSON.stringify({ score: result.score, band: scoreBand(result.score), counts: countBySeverity(result.findings) }, null, 2)
  }
  return JSON.stringify(
    {
      ...result,
      band: scoreBand(result.score),
      counts: countBySeverity(result.findings),
      findings,
      recommendations: recommendations(result),
    },
    null,
    2
  )
}
