import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react'

const KEY = 'soc-ops-academy.progress.v1'

export interface Progress {
  coursesRead: Record<string, string[]>
  quizBest: Record<string, number>
  alerts: Record<string, number>
  playbookSteps: Record<string, string[]>
  labMissions: string[]
}

const EMPTY: Progress = { coursesRead: {}, quizBest: {}, alerts: {}, playbookSteps: {}, labMissions: [] }

export const XP_RULES = {
  course: 50,
  quiz: 100,
  alert: 150,
  playbook: 60,
  mission: 25,
}

export const RANKS = [
  { name: 'Analyste Junior N1', min: 0 },
  { name: 'Analyste Confirmé N2', min: 700 },
  { name: 'Threat Hunter N3', min: 1500 },
  { name: 'SOC Lead', min: 2300 },
]

export interface Totals {
  sectionsByModule: Record<string, number>
  stepsByPlaybook: Record<string, number>
}

/** L'XP est dérivée de l'état : refaire un quiz ou une alerte n'augmente que le meilleur score. */
export function computeXp(p: Progress, t: Totals): number {
  let xp = 0
  for (const [id, total] of Object.entries(t.sectionsByModule)) {
    if ((p.coursesRead[id]?.length ?? 0) >= total) xp += XP_RULES.course
  }
  for (const score of Object.values(p.quizBest)) xp += Math.round((score / 100) * XP_RULES.quiz)
  for (const score of Object.values(p.alerts)) xp += Math.round((score / 100) * XP_RULES.alert)
  for (const [id, total] of Object.entries(t.stepsByPlaybook)) {
    if ((p.playbookSteps[id]?.length ?? 0) >= total) xp += XP_RULES.playbook
  }
  return xp + p.labMissions.length * XP_RULES.mission
}

export function rankFor(xp: number) {
  let index = 0
  RANKS.forEach((r, i) => {
    if (xp >= r.min) index = i
  })
  const next = RANKS[index + 1]
  const ratio = next ? (xp - RANKS[index].min) / (next.min - RANKS[index].min) : 1
  return { rank: RANKS[index], next, ratio: Math.min(1, ratio) }
}

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v)

function scoreMap(v: unknown): Record<string, number> {
  if (!isRecord(v)) return {}
  return Object.fromEntries(Object.entries(v).filter((e): e is [string, number] => typeof e[1] === 'number' && e[1] >= 0 && e[1] <= 100))
}

function stringList(v: unknown): string[] {
  return Array.isArray(v) ? v.filter((x): x is string => typeof x === 'string') : []
}

function listMap(v: unknown): Record<string, string[]> {
  if (!isRecord(v)) return {}
  return Object.fromEntries(Object.entries(v).map(([k, list]) => [k, stringList(list)]))
}

/** Une sauvegarde abîmée ou modifiée à la main ne doit jamais empêcher le site de démarrer. */
export function sanitizeProgress(raw: unknown): Progress {
  const o = isRecord(raw) ? raw : {}
  return {
    coursesRead: listMap(o.coursesRead),
    quizBest: scoreMap(o.quizBest),
    alerts: scoreMap(o.alerts),
    playbookSteps: listMap(o.playbookSteps),
    labMissions: stringList(o.labMissions),
  }
}

function load(): Progress {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? sanitizeProgress(JSON.parse(raw)) : EMPTY
  } catch {
    return EMPTY
  }
}

const DRAFT_PREFIX = 'soc-ops-academy.ticket.'

/** Brouillon d'un ticket : l'analyste doit pouvoir partir décoder une charge dans le CyberLab et revenir. */
export function loadTicketDraft(alertId: string): unknown {
  try {
    return JSON.parse(localStorage.getItem(DRAFT_PREFIX + alertId) ?? 'null')
  } catch {
    return null
  }
}

export function saveTicketDraft(alertId: string, draft: unknown) {
  try {
    localStorage.setItem(DRAFT_PREFIX + alertId, JSON.stringify(draft))
  } catch {
    // Stockage indisponible : le brouillon reste dans le formulaire tant que la page est ouverte.
  }
}

function clearTicketDrafts() {
  try {
    for (const key of Object.keys(localStorage)) if (key.startsWith(DRAFT_PREFIX)) localStorage.removeItem(key)
  } catch {
    // Stockage indisponible : rien à effacer.
  }
}

interface Ctx {
  progress: Progress
  toggleSection: (moduleId: string, sectionId: string) => void
  saveQuiz: (moduleId: string, score: number) => void
  saveAlert: (alertId: string, score: number) => void
  toggleStep: (playbookId: string, stepId: string) => void
  completeMission: (id: string) => void
  reset: () => void
}

const ProgressContext = createContext<Ctx | null>(null)

function toggle(list: string[] | undefined, value: string) {
  const l = list ?? []
  return l.includes(value) ? l.filter((v) => v !== value) : [...l, value]
}

export function ProgressProvider({ children }: { children: ReactNode }) {
  const [progress, setProgress] = useState<Progress>(load)

  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(progress))
    } catch {
      // Stockage indisponible (navigation privée) : la progression reste en mémoire.
    }
  }, [progress])

  // Sans cela, deux onglets ouverts s'écrasent mutuellement leur progression.
  useEffect(() => {
    const onStorage = (e: StorageEvent) => {
      if (e.key === KEY || e.key === null) setProgress(load())
    }
    window.addEventListener('storage', onStorage)
    return () => window.removeEventListener('storage', onStorage)
  }, [])

  const toggleSection = useCallback((m: string, s: string) => {
    setProgress((p) => ({ ...p, coursesRead: { ...p.coursesRead, [m]: toggle(p.coursesRead[m], s) } }))
  }, [])
  const saveQuiz = useCallback((m: string, score: number) => {
    setProgress((p) => ({ ...p, quizBest: { ...p.quizBest, [m]: Math.max(score, p.quizBest[m] ?? 0) } }))
  }, [])
  const saveAlert = useCallback((a: string, score: number) => {
    setProgress((p) => ({ ...p, alerts: { ...p.alerts, [a]: Math.max(score, p.alerts[a] ?? 0) } }))
  }, [])
  const toggleStep = useCallback((b: string, s: string) => {
    setProgress((p) => ({ ...p, playbookSteps: { ...p.playbookSteps, [b]: toggle(p.playbookSteps[b], s) } }))
  }, [])
  const completeMission = useCallback((id: string) => {
    setProgress((p) => (p.labMissions.includes(id) ? p : { ...p, labMissions: [...p.labMissions, id] }))
  }, [])
  const reset = useCallback(() => {
    clearTicketDrafts()
    setProgress(EMPTY)
  }, [])

  const value = useMemo(
    () => ({ progress, toggleSection, saveQuiz, saveAlert, toggleStep, completeMission, reset }),
    [progress, toggleSection, saveQuiz, saveAlert, toggleStep, completeMission, reset],
  )
  return <ProgressContext.Provider value={value}>{children}</ProgressContext.Provider>
}

export function useProgress() {
  const ctx = useContext(ProgressContext)
  if (!ctx) throw new Error('useProgress doit être utilisé dans ProgressProvider')
  return ctx
}
