import { modules } from '../data/modules'
import { playbooks } from '../data/playbooks'
import type { Totals } from './progress'

export const totals: Totals = {
  sectionsByModule: Object.fromEntries(modules.map((m) => [m.id, m.sections.length])),
  stepsByPlaybook: Object.fromEntries(
    playbooks.map((b) => [b.id, b.phases.reduce((n, phase) => n + phase.steps.length, 0)]),
  ),
}
