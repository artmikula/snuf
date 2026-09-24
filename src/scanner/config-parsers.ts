import { readFileSync } from 'node:fs'

export function readText(path: string, maxBytes = 2_000_000): string | undefined {
  try {
    const content = readFileSync(path, 'utf-8')
    return content.length > maxBytes ? undefined : content
  } catch {
    return undefined
  }
}

export function stripJsonComments(text: string): string {
  let out = ''
  let inString = false
  let quote = ''
  for (let i = 0; i < text.length; i++) {
    const ch = text[i]!
    const next = text[i + 1]
    if (inString) {
      out += ch
      if (ch === '\\') {
        out += next ?? ''
        i++
      } else if (ch === quote) {
        inString = false
      }
      continue
    }
    if (ch === '"' || ch === "'") {
      inString = true
      quote = ch
      out += ch
      continue
    }
    if (ch === '/' && next === '/') {
      while (i < text.length && text[i] !== '\n') i++
      out += '\n'
      continue
    }
    if (ch === '/' && next === '*') {
      i += 2
      while (i < text.length && !(text[i] === '*' && text[i + 1] === '/')) i++
      i++
      continue
    }
    out += ch
  }
  return out.replace(/,(\s*[}\]])/g, '$1')
}

export function readJson(path: string): unknown {
  const text = readText(path)
  if (text === undefined) return undefined
  try {
    return JSON.parse(text)
  } catch {
    try {
      return JSON.parse(stripJsonComments(text))
    } catch {
      return undefined
    }
  }
}

type TomlValue = string | number | boolean | string[] | Record<string, unknown>

function parseTomlScalar(raw: string): TomlValue {
  const v = raw.trim()
  if (v.startsWith('"') && v.endsWith('"')) return v.slice(1, -1).replace(/\\"/g, '"')
  if (v.startsWith("'") && v.endsWith("'")) return v.slice(1, -1)
  if (v.startsWith('[') && v.endsWith(']')) {
    const inner = v.slice(1, -1).trim()
    if (!inner) return []
    return inner
      .split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)
      .map((s) => s.trim())
      .filter(Boolean)
      .map((s) => String(parseTomlScalar(s)))
  }
  if (v === 'true') return true
  if (v === 'false') return false
  if (/^-?\d+(\.\d+)?$/.test(v)) return Number(v)
  return v
}

export function parseTomlSubset(text: string): Record<string, unknown> {
  const root: Record<string, unknown> = {}
  let current: Record<string, unknown> = root
  for (const rawLine of text.split('\n')) {
    const line = rawLine.replace(/\s#.*$/, '').trim()
    if (!line || line.startsWith('#')) continue
    const table = line.match(/^\[([^\]]+)\]$/)
    if (table) {
      const parts = table[1]!.split('.').map((p) => p.trim().replace(/^"|"$/g, ''))
      current = root
      for (const part of parts) {
        if (typeof current[part] !== 'object' || current[part] === null) current[part] = {}
        current = current[part] as Record<string, unknown>
      }
      continue
    }
    const eq = line.indexOf('=')
    if (eq === -1) continue
    const key = line.slice(0, eq).trim().replace(/^"|"$/g, '')
    const value = line.slice(eq + 1).trim()
    const inlineTable = value.match(/^\{(.*)\}$/)
    if (inlineTable) {
      const obj: Record<string, unknown> = {}
      for (const pair of inlineTable[1]!.split(/,(?=(?:[^"]*"[^"]*")*[^"]*$)/)) {
        const pe = pair.indexOf('=')
        if (pe === -1) continue
        obj[pair.slice(0, pe).trim().replace(/^"|"$/g, '')] = parseTomlScalar(pair.slice(pe + 1))
      }
      current[key] = obj
      continue
    }
    current[key] = parseTomlScalar(value)
  }
  return root
}

export function parseEnvFile(text: string): Record<string, string> {
  const result: Record<string, string> = {}
  for (const rawLine of text.split('\n')) {
    let line = rawLine.trim()
    if (!line || line.startsWith('#')) continue
    if (line.startsWith('export ')) line = line.slice(7).trim()
    const eq = line.indexOf('=')
    if (eq === -1) continue
    const key = line.slice(0, eq).trim()
    let value = line.slice(eq + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    } else {
      value = value.replace(/\s+#.*$/, '')
    }
    if (key) result[key] = value
  }
  return result
}

export function walkStrings(
  value: unknown,
  visit: (path: string, str: string) => void,
  path = '',
  depth = 0
): void {
  if (depth > 6 || value === null || value === undefined) return
  if (typeof value === 'string') {
    visit(path, value)
    return
  }
  if (Array.isArray(value)) {
    value.forEach((v, i) => walkStrings(v, visit, `${path}[${i}]`, depth + 1))
    return
  }
  if (typeof value === 'object') {
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      walkStrings(v, visit, path ? `${path}.${k}` : k, depth + 1)
    }
  }
}
