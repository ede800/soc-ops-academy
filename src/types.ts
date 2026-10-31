export type Lang = 'kql' | 'spl' | 'yaml' | 'powershell' | 'bash' | 'log' | 'text' | 'email'

export type Block =
  | { type: 'p'; text: string }
  | { type: 'h'; text: string }
  | { type: 'list'; items: string[]; ordered?: boolean }
  | { type: 'table'; headers: string[]; rows: string[][] }
  | { type: 'code'; lang: Lang; title?: string; code: string }
  | { type: 'callout'; tone: 'info' | 'warn' | 'danger' | 'tip'; title: string; text: string }
  | { type: 'links'; items: { to: string; label: string }[] }

export interface QuizQuestion {
  q: string
  /** Extrait de log à analyser : transforme la question en mini-lab. */
  evidence?: { lang: Lang; code: string }
  options: string[]
  answer: number
  explain: string
}

export interface CourseSection {
  id: string
  title: string
  blocks: Block[]
}

export interface Module {
  id: string
  number: number
  title: string
  tier: 'N1' | 'N1-N2' | 'N2' | 'N2-N3' | 'N3'
  summary: string
  objectives: string[]
  sections: CourseSection[]
  cheatSheet: Block[]
  quiz: QuizQuestion[]
}

export type Severity = 'Critique' | 'Haute' | 'Moyenne' | 'Basse'
export type Classification = 'TP' | 'FP' | 'B-TP'

export interface ProcessNode {
  name: string
  cmd?: string
  user?: string
  pid?: number
  flag?: string
  children?: ProcessNode[]
}

export interface IntelItem {
  type: 'IP' | 'Domaine' | 'SHA-256' | 'URL' | 'Compte' | 'Contexte'
  value: string
  verdict: 'Malveillant' | 'Suspect' | 'Légitime' | 'Inconnu'
  detail: string
}

export interface SiemAlert {
  id: string
  title: string
  severity: Severity
  source: string
  rule: string
  time: string
  host: string
  user: string
  summary: string
  logs: { title: string; lang: Lang; content: string }[]
  tree?: ProcessNode
  /** Précise la nature de l'arbre lorsqu'il ne s'agit pas de processus (incident cloud). */
  treeNote?: string
  intel: IntelItem[]
  solution: {
    classification: Classification
    tactics: string[]
    actions: string[]
    partialActions?: string[]
    /** Chaque groupe vaut un point : un seul mot du groupe suffit. */
    reportKeywords: { label: string; anyOf: string[] }[]
    debrief: string
    modelReport: string
    pitfall: string
  }
}

export interface PlaybookStep {
  title: string
  detail: string
  code?: { lang: Lang; title?: string; code: string }
  decision?: string
}

export interface PlaybookPhase {
  name: 'Identification' | 'Confinement' | 'Éradication' | 'Restauration' | 'Clôture'
  steps: PlaybookStep[]
}

export interface Playbook {
  id: string
  title: string
  severity: Severity
  sla: string
  trigger: string
  roles: string
  mitre: string[]
  phases: PlaybookPhase[]
  closure: string[]
  pitfalls: string[]
}

export interface Technique {
  id: string
  name: string
  tactic: string
  how: string
  logs: string[]
  kql: string
  spl: string
  falsePositives: string
}

export interface CheatEntry {
  id: string
  category: 'Windows' | 'Sysmon' | 'Logon Type' | 'Code d’erreur' | 'Port' | 'LOLBin' | 'Linux' | 'Entra ID'
  title: string
  meaning: string
  malicious: string
}
