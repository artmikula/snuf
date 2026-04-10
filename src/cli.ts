import { Command } from 'commander'
import { writeFileSync } from 'node:fs'
import { runScan } from './scanner/index.js'
import { renderTerminal } from './reporter/terminal.js'
import { renderMarkdown } from './reporter/markdown.js'
import { renderJson } from './reporter/json.js'
import type { ScanOptions } from './types.js'

const program = new Command()

program
  .name('snuf')
  .description('Sniff out what AI agents can do on your machine')
  .version('0.1.0')
  .option('--format <type>', 'Output format: terminal, json, markdown', 'terminal')
  .option('--output <path>', 'Save report to file')
  .option('--agent <name>', 'Scan specific agent only (e.g. claude-code, cursor)')
  .option('--severity <level>', 'Minimum severity: info, low, medium, high, critical')
  .option('--quick', 'Just show the score')
  .option('--project <path>', 'Scan a specific project directory')
  .action(async (options: ScanOptions) => {
    const results = await runScan(options)

    if (options.format === 'json') {
      const output = renderJson(results)
      if (options.output) {
        writeFileSync(options.output, output)
        console.log(`Report saved to ${options.output}`)
      } else {
        console.log(output)
      }
      return
    }

    if (options.format === 'markdown') {
      const output = renderMarkdown(results, options)
      if (options.output) {
        writeFileSync(options.output, output)
        console.log(`Report saved to ${options.output}`)
      } else {
        console.log(output)
      }
      return
    }

    // default: terminal
    renderTerminal(results, options)
    if (options.output) {
      console.log(`Note: --output only writes content for --format json or --format markdown`)
    }
  })

program.parse()
