import type { SiemAlert } from '../types'

export interface ReportFields {
  qui: string
  quoi: string
  quand: string
  ou: string
  pourquoi: string
  verdict: string
}

export interface Decision {
  classification: string
  tactic: string
  action: string
  report: ReportFields
}

export const EMPTY_REPORT: ReportFields = { qui: '', quoi: '', quand: '', ou: '', pourquoi: '', verdict: '' }

export const REPORT_LABELS: Record<keyof ReportFields, { label: string; hint: string }> = {
  qui: { label: 'Qui', hint: 'Compte, utilisateur, machine ou acteur à l’origine de l’action' },
  quoi: { label: 'Quoi', hint: 'Ce qui s’est produit, avec les preuves techniques' },
  quand: { label: 'Quand', hint: 'Horodatage UTC, début et fin observés' },
  ou: { label: 'Où', hint: 'Hôtes, IP, tenant, chemins impactés' },
  pourquoi: { label: 'Pourquoi', hint: 'Votre raisonnement : ce qui fait pencher vers ce verdict' },
  verdict: { label: 'Verdict', hint: 'TP, FP ou B-TP, actions menées et suite à donner' },
}

/** Découpe un rapport modèle « Qui : … / Quoi : … » en champs. */
export function parseModelReport(text: string): ReportFields {
  const out = { ...EMPTY_REPORT }
  const byLabel: Record<string, keyof ReportFields> = { Qui: 'qui', Quoi: 'quoi', Quand: 'quand', Où: 'ou', Pourquoi: 'pourquoi', Verdict: 'verdict' }
  for (const line of text.split('\n')) {
    const m = /^(Qui|Quoi|Quand|Où|Pourquoi|Verdict) : (.*)$/.exec(line)
    if (m) out[byLabel[m[1]]] = m[2]
  }
  return out
}

const normalize = (s: string) =>
  s
    .toLowerCase()
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')

/** Classification annoncée dans le verdict écrit, en ignorant les négations (« pas un faux positif »). */
export function verdictClassification(text: string): string | null {
  const t = normalize(text).replace(/\b(?:pas|ni|non)\s+(?:un\s+|une\s+|de\s+)?(?:faux positif|vrai positif benin|vrai positif|b-?tp|fp|tp|benin)\b/g, ' ')
  if (/\bb-?tp\b|\bbenin/.test(t)) return 'B-TP'
  if (/\bfp\b|faux positif/.test(t)) return 'FP'
  if (/\btp\b|vrai positif/.test(t)) return 'TP'
  return null
}

export interface ScoreDetail {
  total: number
  classification: { points: number; ok: boolean }
  tactic: { points: number; ok: boolean }
  action: { points: number; ok: boolean; partial: boolean }
  report: {
    points: number
    verdictConflict: boolean
    missingFields: string[]
    thinFields: string[]
    keywordsFound: string[]
    keywordsMissing: string[]
  }
}

/**
 * Barème sur 100 : classification 40, tactique 15, action 20, rapport 25.
 * Le rapport est corrigé par heuristique : champs remplis, densité et présence des preuves attendues.
 */
export function scoreDecision(alert: SiemAlert, d: Decision): ScoreDetail {
  const s = alert.solution
  const classOk = d.classification === s.classification
  const tacticOk = s.tactics.includes(d.tactic)
  const actionOk = s.actions.includes(d.action)
  const actionPartial = !actionOk && (s.partialActions?.includes(d.action) ?? false)

  const keys = Object.keys(REPORT_LABELS) as (keyof ReportFields)[]
  const missingFields = keys.filter((k) => !d.report[k].trim()).map((k) => REPORT_LABELS[k].label)
  const thinFields = keys
    .filter((k) => d.report[k].trim() && d.report[k].trim().length < 15 && k !== 'quand' && k !== 'qui' && k !== 'ou')
    .map((k) => REPORT_LABELS[k].label)

  const body = normalize(Object.values(d.report).join(' '))
  const found: string[] = []
  const missing: string[] = []
  for (const group of s.reportKeywords) {
    if (group.anyOf.some((w) => body.includes(normalize(w)))) found.push(group.label)
    else missing.push(group.label)
  }

  const structure = ((keys.length - missingFields.length - thinFields.length * 0.5) / keys.length) * 10
  const evidence = s.reportKeywords.length ? (found.length / s.reportKeywords.length) * 15 : 15
  const written = verdictClassification(d.report.verdict)
  const verdictConflict = written !== null && written !== d.classification
  const reportPoints = Math.max(0, Math.round(Math.max(0, structure) + evidence) - (verdictConflict ? 5 : 0))

  const classification = classOk ? 40 : 0
  const tactic = tacticOk ? 15 : 0
  const action = actionOk ? 20 : actionPartial ? 10 : 0

  return {
    total: classification + tactic + action + reportPoints,
    classification: { points: classification, ok: classOk },
    tactic: { points: tactic, ok: tacticOk },
    action: { points: action, ok: actionOk, partial: actionPartial },
    report: { points: reportPoints, verdictConflict, missingFields, thinFields, keywordsFound: found, keywordsMissing: missing },
  }
}
