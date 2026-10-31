import { cheatEntries } from '../data/cheatSheets'
import { techniques } from '../data/mitre'
import { modules } from '../data/modules'
import { playbooks } from '../data/playbooks'
import { siemAlerts } from '../data/siemAlerts'

export type HitKind = 'Référence' | 'MITRE' | 'Module' | 'Playbook' | 'Alerte'

export interface SearchHit {
  key: string
  kind: HitKind
  label: string
  title: string
  meaning?: string
  malicious?: string
  to: string
  haystack: string
  exact: string
}

const norm = (s: string) =>
  s
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')

function make(h: Omit<SearchHit, 'haystack' | 'exact'> & { extra?: string }): SearchHit {
  const { extra = '', ...rest } = h
  return {
    ...rest,
    haystack: norm([h.label, h.title, h.meaning, h.malicious, extra].filter(Boolean).join(' ')),
    exact: norm(h.label),
  }
}

/** Toutes les chaînes d'un contenu imbriqué : un cours se trouve aussi par ce qu'il contient, pas seulement par son titre. */
function allText(value: unknown): string {
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map(allText).join(' ')
  if (typeof value === 'object' && value !== null) return allText(Object.values(value))
  return ''
}

export const searchIndex: SearchHit[] = [
  ...cheatEntries.map((e) =>
    make({
      key: `cheat-${e.category}-${e.id}`,
      kind: 'Référence',
      label: e.id,
      title: `${e.title} · ${e.category}`,
      meaning: e.meaning,
      malicious: e.malicious,
      to: `/cheat-sheets?q=${encodeURIComponent(e.id)}`,
    }),
  ),
  ...techniques.map((t) =>
    make({
      key: `mitre-${t.id}`,
      kind: 'MITRE',
      label: t.id,
      title: `${t.name} · ${t.tactic}`,
      meaning: t.how,
      to: `/mitre?t=${encodeURIComponent(t.id)}`,
      extra: t.logs.join(' '),
    }),
  ),
  ...modules.map((m) =>
    make({
      key: `mod-${m.id}`,
      kind: 'Module',
      label: `Module ${m.number}`,
      title: m.title,
      meaning: m.summary,
      to: `/modules/${m.id}`,
      extra: allText(m.sections),
    }),
  ),
  ...playbooks.map((b) =>
    make({ key: `pb-${b.id}`, kind: 'Playbook', label: b.mitre[0], title: b.title, meaning: b.trigger, to: `/playbooks/${b.id}`, extra: `${b.mitre.join(' ')} ${allText(b.phases)}` }),
  ),
  ...siemAlerts.map((a) =>
    make({ key: `al-${a.id}`, kind: 'Alerte', label: a.id, title: a.title, meaning: a.summary, to: `/soc-queue/${a.id}`, extra: a.rule }),
  ),
]

/** Tous les termes doivent être présents ; un identifiant exact passe devant le reste, puis les titres. */
export function search(query: string, limit = 30): SearchHit[] {
  const q = norm(query.trim())
  if (!q) return []
  const terms = q.split(/\s+/)
  const scored: { hit: SearchHit; score: number }[] = []
  for (const hit of searchIndex) {
    if (!terms.every((t) => hit.haystack.includes(t))) continue
    let score = 0
    if (hit.exact === q) score += 100
    else if (hit.exact.split(/[\s/-]+/).includes(q)) score += 80
    else if (hit.exact.startsWith(q)) score += 50
    else if (hit.exact.includes(q)) score += 25
    if (norm(hit.title).includes(q)) score += 10
    if (hit.kind === 'Référence') score += 2
    scored.push({ hit, score })
  }
  return scored
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((s) => s.hit)
}
