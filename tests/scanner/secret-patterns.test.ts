import { describe, it, expect } from 'vitest'
import { classifySecret, mask, looksLikePlaceholder } from '../../src/scanner/secret-patterns.js'

describe('classifySecret', () => {
  it('recognizes well known value formats regardless of key name', () => {
    expect(classifySecret('FOO', 'sk-ant-api03-' + 'x'.repeat(40))?.label).toBe('Anthropic API key')
    expect(classifySecret('FOO', 'ghp_' + 'a'.repeat(36))?.label).toBe('GitHub token')
    expect(classifySecret('FOO', 'AKIAIOSFODNN7EXAMPLE')?.label).toBe('AWS access key')
    expect(classifySecret('FOO', 'xoxb-1234-5678-abcdefgh')?.label).toBe('Slack token')
    expect(classifySecret('FOO', 'postgres://user:pass@db.example.com/app')?.label).toBe('URL with embedded credentials')
  })

  it('recognizes secret looking key names', () => {
    expect(classifySecret('OPENAI_API_KEY', 'whatever-value-here')?.label).toBe('OpenAI API key')
    expect(classifySecret('SUPABASE_SERVICE_ROLE_KEY', 'abc')?.label).toBe('Supabase service role key')
    expect(classifySecret('MY_SERVICE_TOKEN', 'abc')?.label).toBe('Credential')
    expect(classifySecret('DB_PASSWORD', 'abc')?.label).toBe('Credential')
  })

  it('ignores names that are clearly not secrets', () => {
    expect(classifySecret('OPENAI_ORG', 'org-123')).toBeUndefined()
    expect(classifySecret('OPENAI_BASE_URL', 'https://api.openai.com')).toBeUndefined()
    expect(classifySecret('NEXT_PUBLIC_API_KEY', 'pk_live_1234567890abcdefghijk')).toBeUndefined()
    expect(classifySecret('LOG_LEVEL', 'debug')).toBeUndefined()
    expect(classifySecret('STRIPE_PUBLISHABLE_KEY', 'abc')).toBeUndefined()
  })

  it('ignores placeholders and env references', () => {
    expect(classifySecret('OPENAI_API_KEY', '')).toBeUndefined()
    expect(classifySecret('OPENAI_API_KEY', 'your-key-here')).toBeUndefined()
    expect(classifySecret('OPENAI_API_KEY', '${OPENAI_API_KEY}')).toBeUndefined()
    expect(classifySecret('OPENAI_API_KEY', '<paste here>')).toBeUndefined()
    expect(classifySecret('OPENAI_API_KEY', 'changeme')).toBeUndefined()
  })

  it('only flags database urls that embed credentials', () => {
    expect(classifySecret('DATABASE_URL', 'postgres://localhost:5432/app')).toBeUndefined()
    expect(classifySecret('DATABASE_URL', 'postgres://admin:hunter2@localhost:5432/app')).toBeDefined()
    expect(classifySecret('DATABASE_URL')).toBeDefined()
  })

  it('masks values without leaking them', () => {
    const masked = mask('sk-ant-api03-abcdefghijklmnopqrstuvwxyz')
    expect(masked).not.toContain('abcdefghijklmnop')
    expect(masked).toMatch(/chars/)
    expect(mask('short')).toBe('****')
    expect(looksLikePlaceholder('xxx')).toBe(true)
  })
})
