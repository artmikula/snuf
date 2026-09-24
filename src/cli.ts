import { Command, Option } from 'commander'
import { writeFileSync } from 'node:fs'
import { homedir } from 'node:os'
import { runScan } from './scanner/index.js'
import { renderTerminal } from './reporter/terminal.js'
import { renderMarkdown } from './reporter/markdown.js'
import { renderJson } from './reporter/json.js'
import { severityRank } from './scoring/risk.js'
import { AGENT_SLUGS } from './agents/index.js'
import { VERSION } from './version.js'
import { SEVERITIES, type ScanOptions, type OutputFormat } from './types.js'

const program = new Command()

program
  .name('snuf')
  .description('Sniff out what AI agents can reach on your machine. Read only, zero network calls.')
  .version(VERSION)
  .addOption(new Option('--format <type>', 'output format').choices(['terminal', 'json', 'markdown']).default('terminal'))
  .option('--output <path>', 'write the report to a file (json or markdown, inferred from extension)')
  .addOption(new Option('--agent <slug>', 'scan one agent only').choices(AGENT_SLUGS))
  .addOption(new Option('--severity <level>', 'hide findings below this level').choices(SEVERITIES))
  .option('--quick', 'print only the score')
  .option('--project <path>', 'project directory to scan (default: current directory)')
  .addOption(new Option('--fail-on <level>', 'exit 1 if any finding is at or above this level').choices(SEVERITIES))
  .action(async (options: ScanOptions) => {
    const home = homedir()
    const result = await runScan(options)

    let fileFormat: OutputFormat | undefined
    if (options.output) {
      fileFormat = options.format !== 'terminal' ? options.format : options.output.endsWith('.json') ? 'json' : 'markdown'
      const content = fileFormat === 'json' ? renderJson(result, options) : renderMarkdown(result, options, home)
      writeFileSync(options.output, content + '\n')
    }

    if (options.format === 'json' && !options.output) console.log(renderJson(result, options))
    else if (options.format === 'markdown' && !options.output) console.log(renderMarkdown(result, options, home))
    else if (options.format === 'terminal') console.log(renderTerminal(result, options, home))
    if (options.output) console.error(`Report written to ${options.output}`)

    if (options.failOn) {
      const threshold = severityRank(options.failOn)
      const hit = result.findings.some((f) => severityRank(f.severity) >= threshold)
      if (hit) process.exitCode = 1
    }
  })

program.parseAsync().catch((err: unknown) => {
  const message = err instanceof Error ? err.message : String(err)
  console.error(`snuf failed: ${message}`)
  process.exitCode = 1
})
