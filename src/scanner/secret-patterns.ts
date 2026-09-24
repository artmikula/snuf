export interface SecretMatch {
  label: string
  confidence: 'value' | 'name'
}

const VALUE_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^sk-ant-[A-Za-z0-9_-]{20,}/, label: 'Anthropic API key' },
  { pattern: /^sk-proj-[A-Za-z0-9_-]{20,}/, label: 'OpenAI API key' },
  { pattern: /^sk-[A-Za-z0-9_-]{32,}/, label: 'API key (sk- prefix)' },
  { pattern: /^(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}/, label: 'GitHub token' },
  { pattern: /^github_pat_[A-Za-z0-9_]{40,}/, label: 'GitHub fine-grained token' },
  { pattern: /^glpat-[A-Za-z0-9_-]{20,}/, label: 'GitLab token' },
  { pattern: /^AKIA[0-9A-Z]{16}$/, label: 'AWS access key' },
  { pattern: /^xox[abprs]-[A-Za-z0-9-]{10,}/, label: 'Slack token' },
  { pattern: /^AIza[0-9A-Za-z_-]{35}$/, label: 'Google API key' },
  { pattern: /^(sk|rk)_(live|test)_[A-Za-z0-9]{20,}/, label: 'Stripe key' },
  { pattern: /^hf_[A-Za-z0-9]{30,}/, label: 'Hugging Face token' },
  { pattern: /^npm_[A-Za-z0-9]{36}/, label: 'npm token' },
  { pattern: /^pypi-[A-Za-z0-9_-]{50,}/, label: 'PyPI token' },
  { pattern: /^dop_v1_[a-f0-9]{64}/, label: 'DigitalOcean token' },
  { pattern: /^SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}/, label: 'SendGrid key' },
  { pattern: /^eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}/, label: 'JWT' },
  { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/, label: 'Private key' },
  { pattern: /^[a-z][a-z0-9+.-]*:\/\/[^\s/:@]+:[^\s/@]+@/i, label: 'URL with embedded credentials' },
]

const NAME_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /^ANTHROPIC_(API_KEY|AUTH_TOKEN)$/i, label: 'Anthropic API key' },
  { pattern: /^OPENAI_API_KEY$/i, label: 'OpenAI API key' },
  { pattern: /^(GITHUB|GH)_(TOKEN|PAT|PERSONAL_ACCESS_TOKEN)$/i, label: 'GitHub token' },
  { pattern: /^GITHUB_PERSONAL_ACCESS_TOKEN$/i, label: 'GitHub token' },
  { pattern: /^GITLAB_TOKEN$/i, label: 'GitLab token' },
  { pattern: /^AWS_(SECRET_ACCESS_KEY|SESSION_TOKEN)$/i, label: 'AWS credential' },
  { pattern: /^AWS_ACCESS_KEY_ID$/i, label: 'AWS access key' },
  { pattern: /^(GOOGLE|GEMINI)_API_KEY$/i, label: 'Google API key' },
  { pattern: /^GOOGLE_APPLICATION_CREDENTIALS$/i, label: 'Google service account path' },
  { pattern: /^SUPABASE_SERVICE_ROLE_KEY$/i, label: 'Supabase service role key' },
  { pattern: /^(AZURE|OPENROUTER|XAI|DEEPSEEK|GROQ|MISTRAL|COHERE|TOGETHER|REPLICATE|PERPLEXITY|FIREWORKS|VOYAGE|ELEVENLABS|ELEVEN|TAVILY|EXA|BRAVE|FIRECRAWL|SERPER|SERPAPI|NOTION|LINEAR|FIGMA|SENTRY|VERCEL|RAILWAY|FLY|SUPABASE|NEON|PLANETSCALE|UPSTASH|PINECONE|WEAVIATE|RESEND|SENDGRID|TWILIO|STRIPE|SHOPIFY|HUBSPOT|AIRTABLE|ZAPIER|BROWSERBASE|APIFY|E2B|CONTEXT7|CLOUDFLARE|DIGITALOCEAN|HEROKU|NETLIFY|DATADOG|NEW_RELIC|PAGERDUTY|OPSGENIE|JIRA|ATLASSIAN|CONFLUENCE|SLACK|DISCORD|TELEGRAM|POSTMAN|HF|HUGGINGFACE|HUGGING_FACE|LANGCHAIN|LANGSMITH|WANDB|PYPI|NPM|DOCKER|DOCKERHUB|GHCR|OBSIDIAN|TODOIST|ASANA|MONDAY|CLICKUP|INTERCOM|ZENDESK|FRESHDESK|MAILGUN|POSTMARK|MAILCHIMP|BREVO|KLAVIYO|SEGMENT|MIXPANEL|AMPLITUDE|POSTHOG|ALGOLIA|TYPESENSE|MEILISEARCH|ELASTIC|OPENSEARCH|MONGODB|MONGO|REDIS|SNOWFLAKE|DATABRICKS|BIGQUERY)_(API_KEY|API_TOKEN|TOKEN|SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|BOT_TOKEN|SERVICE_ROLE_KEY|PASSWORD|PRIVATE_KEY)$/i, label: 'Service credential' },
  { pattern: /^SLACK_(BOT|USER|APP)_TOKEN$/i, label: 'Slack token' },
  { pattern: /^(STRIPE|TWILIO|SENDGRID|RESEND)_(SECRET|API)_KEY$/i, label: 'Service credential' },
  { pattern: /^(NPM|PYPI|HF|HUGGINGFACE)_TOKEN$/i, label: 'Registry token' },
  { pattern: /^(OAUTH|CLIENT)_SECRET$/i, label: 'OAuth client secret' },
  { pattern: /(^|_)(API_KEY|APIKEY|API_TOKEN|ACCESS_TOKEN|AUTH_TOKEN|SECRET_KEY|SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|ENCRYPTION_KEY|SIGNING_KEY|CLIENT_SECRET|WEBHOOK_SECRET)$/i, label: 'Credential' },
]

const DB_URL_NAME = /^(DATABASE|POSTGRES|POSTGRESQL|MYSQL|REDIS|MONGO|MONGODB|DIRECT|PRISMA)_(URL|URI|CONNECTION_STRING)$/i

const SAFE_NAME = /(PUBLIC|PUBLISHABLE|_ORG(_ID)?$|_ID$|_URL$|_HOST$|_PORT$|_NAME$|_PATH$|_FILE$|_DIR$|_MODEL$|_REGION$|_ENDPOINT$|_BASE_URL$|_TIMEOUT$|_ENABLED$|_DEBUG$|_LOG)/i

const PLACEHOLDER = /^(|\s*|\$\{.*\}|\$[A-Z_]+|<.*>|your[-_ ].*|xxx+|\*+|changeme|change_me|placeholder|todo|null|undefined|true|false|none|example|test|dummy|sk-\.\.\.|\.\.\.)$/i

export function looksLikePlaceholder(value: string | undefined): boolean {
  if (value === undefined) return true
  return PLACEHOLDER.test(value.trim())
}

export function classifyValue(value: string | undefined): SecretMatch | undefined {
  if (!value || looksLikePlaceholder(value)) return undefined
  const trimmed = value.trim().replace(/^["']|["']$/g, '')
  for (const { pattern, label } of VALUE_PATTERNS) {
    if (pattern.test(trimmed)) return { label, confidence: 'value' }
  }
  return undefined
}

export function classifyName(key: string): SecretMatch | undefined {
  if (DB_URL_NAME.test(key)) return { label: 'Database connection string', confidence: 'name' }
  if (SAFE_NAME.test(key)) return undefined
  for (const { pattern, label } of NAME_PATTERNS) {
    if (pattern.test(key)) return { label, confidence: 'name' }
  }
  return undefined
}

export function classifySecret(key: string, value?: string): SecretMatch | undefined {
  const byValue = classifyValue(value)
  if (byValue) return byValue
  const byName = classifyName(key)
  if (!byName) return undefined
  if (value !== undefined && looksLikePlaceholder(value)) return undefined
  if (byName.label === 'Database connection string') {
    if (value === undefined) return byName
    return /:\/\/[^/\s:@]+:[^/\s@]+@/.test(value) ? byName : undefined
  }
  return byName
}

export function mask(value: string | undefined): string {
  if (value === undefined) return ''
  const v = value.trim()
  if (v.length <= 8) return '****'
  return `${v.slice(0, 4)}…${v.slice(-2)} (${v.length} chars)`
}
