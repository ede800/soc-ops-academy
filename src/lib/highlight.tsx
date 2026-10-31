import type { ReactNode } from 'react'
import type { Lang } from '../types'

type Rule = [RegExp, string]

const COMMON: Rule[] = [
  [/^"(?:[^"\\\n]|\\.)*"/, 'tok-str'],
  [/^'(?:[^'\\\n]|\\.)*'/, 'tok-str'],
  [/^0x[0-9a-fA-F]+\b/, 'tok-num'],
  [/^\b\d+(?:\.\d+)*\b/, 'tok-num'],
]

const RULES: Record<Lang, Rule[]> = {
  kql: [
    [/^\/\/[^\n]*/, 'tok-com'],
    ...COMMON,
    [/^\b(?:where|summarize|project|extend|join|union|order|sort|take|top|parse|mv-expand|distinct|by|on|kind|let|has|has_any|has_all|contains|startswith|endswith|in|and|or|not|matches|regex|render|bin|between|asc|desc|ago)\b/i, 'tok-kw'],
    [/^\b[a-zA-Z_]+(?=\()/, 'tok-fn'],
  ],
  spl: [
    [/^`[^`\n]*`/, 'tok-com'],
    ...COMMON,
    [/^\b(?:index|sourcetype|source|host|search|stats|eval|where|table|rex|sort|head|tail|dedup|eventstats|streamstats|timechart|bin|by|as|AND|OR|NOT|fields|rename|lookup|join|transaction|tstats)\b/, 'tok-kw'],
    [/^\b[a-zA-Z_]+(?=\()/, 'tok-fn'],
  ],
  yaml: [
    [/^#[^\n]*/, 'tok-com'],
    ...COMMON,
    [/^[\w.|-]+(?=:(?:\s|$))/, 'tok-key'],
    [/^\b(?:and|or|not|of|them|true|false)\b/, 'tok-kw'],
  ],
  powershell: [
    [/^#[^\n]*/, 'tok-com'],
    ...COMMON,
    [/^\$[\w:]+/, 'tok-key'],
    [/^\b[A-Z][a-z]+-[A-Za-z]+\b/, 'tok-fn'],
    [/^-[A-Za-z][\w:$]*/, 'tok-kw'],
  ],
  bash: [
    [/^#[^\n]*/, 'tok-com'],
    ...COMMON,
    [/^\b(?:grep|awk|sort|uniq|zgrep|sudo|cat|tail|head|cut|ausearch|journalctl|find|last|lastb|ss|ps|lsof|crontab|sed|wc|tshark|zeek-cut)\b/, 'tok-kw'],
    [/^\s-{1,2}[A-Za-z][\w-]*/, 'tok-fn'],
  ],
  log: [
    ...COMMON,
    [/^\b(?:FAILED|Failed|DENIED|denied|ERROR|fail|softfail|BLOCK|DROP|hidden|Bypass)\b/, 'tok-bad'],
    [/^[\w.-]+(?==)/, 'tok-key'],
    [/^[A-Z][\w-]+(?=:\s)/, 'tok-key'],
  ],
  email: [
    [/^[A-Za-z][\w-]+(?=:\s)/, 'tok-key'],
    [/^\b(?:fail|softfail|none|permerror|temperror)\b/, 'tok-bad'],
    [/^\b(?:pass)\b/, 'tok-str'],
    [/^\b\d+(?:\.\d+){3}\b/, 'tok-num'],
  ],
  text: [],
}

/** Petit tokenizer sans dépendance : découpe le texte en <span> échappés par React. */
export function highlight(code: string, lang: Lang): ReactNode[] {
  const rules = RULES[lang]
  if (!rules.length) return [code]
  const out: ReactNode[] = []
  let rest = code
  let plain = ''
  let key = 0
  let prev = ''
  while (rest.length) {
    const startsWord = !/[\w$-]/.test(prev)
    let hit = false
    if (startsWord || /^["'/#`]/.test(rest)) {
      for (const [re, cls] of rules) {
        const m = re.exec(rest)
        if (m && m[0].length) {
          if (plain) {
            out.push(plain)
            plain = ''
          }
          out.push(
            <span key={key++} className={cls}>
              {m[0]}
            </span>,
          )
          rest = rest.slice(m[0].length)
          prev = m[0].at(-1) ?? ''
          hit = true
          break
        }
      }
    }
    if (!hit) {
      plain += rest[0]
      prev = rest[0]
      rest = rest.slice(1)
    }
  }
  if (plain) out.push(plain)
  return out
}
