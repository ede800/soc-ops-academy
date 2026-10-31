import { ArrowRight, BookOpen, ClipboardList, FlaskConical, RotateCcw, Siren, Trophy } from 'lucide-react'
import { Link } from 'react-router-dom'
import { Card, PageHeader, ProgressBar, btnGhost, btnPrimary } from '../components/ui'
import { modules } from '../data/modules'
import { playbooks } from '../data/playbooks'
import { siemAlerts } from '../data/siemAlerts'
import { RANKS, computeXp, rankFor, useProgress, type Progress } from '../lib/progress'
import { totals } from '../lib/totals'
import { LAB_MISSION_COUNT } from './CyberLab'

function nextStep(p: Progress): { label: string; detail: string; to: string } {
  for (const m of modules) {
    if ((p.coursesRead[m.id]?.length ?? 0) < m.sections.length) {
      return { label: `Module ${m.number} : ${m.title}`, detail: 'Terminez le cours avant de passer au quiz.', to: `/modules/${m.id}` }
    }
    if ((p.quizBest[m.id] ?? 0) < 70) {
      return { label: `Quiz du module ${m.number}`, detail: 'Il faut 70 % pour valider le module.', to: `/modules/${m.id}#quiz` }
    }
  }
  const alert = siemAlerts.find((a) => (p.alerts[a.id] ?? 0) < 80)
  if (alert) return { label: `Ticket ${alert.id} : ${alert.title}`, detail: 'Visez au moins 80 points sur chaque ticket.', to: `/soc-queue/${alert.id}` }
  const book = playbooks.find((b) => (p.playbookSteps[b.id]?.length ?? 0) < totals.stepsByPlaybook[b.id])
  if (book) return { label: book.title, detail: 'Parcourez le playbook jusqu’à la clôture.', to: `/playbooks/${book.id}` }
  return { label: 'Parcours terminé', detail: 'Rejouez les tickets ou explorez la matrice MITRE ATT&CK.', to: '/mitre' }
}

export function Dashboard() {
  const { progress, reset } = useProgress()
  const xp = computeXp(progress, totals)
  const { rank, next, ratio } = rankFor(xp)
  const step = nextStep(progress)

  const coursesDone = modules.filter((m) => (progress.coursesRead[m.id]?.length ?? 0) >= m.sections.length).length
  const quizzesPassed = modules.filter((m) => (progress.quizBest[m.id] ?? 0) >= 70).length
  const alertsDone = Object.keys(progress.alerts).length
  const booksDone = playbooks.filter((b) => (progress.playbookSteps[b.id]?.length ?? 0) >= totals.stepsByPlaybook[b.id]).length

  const stats = [
    { icon: BookOpen, label: 'Modules validés', value: quizzesPassed, total: modules.length, sub: `${coursesDone} cours terminés`, to: '/modules' },
    { icon: Siren, label: 'Tickets traités', value: alertsDone, total: siemAlerts.length, sub: 'Live SOC Queue', to: '/soc-queue' },
    { icon: ClipboardList, label: 'Playbooks parcourus', value: booksDone, total: playbooks.length, sub: 'Réponse à incident', to: '/playbooks' },
    { icon: FlaskConical, label: 'Missions CyberLab', value: progress.labMissions.length, total: LAB_MISSION_COUNT, sub: 'Décodage et artefacts', to: '/cyberlab' },
  ]

  return (
    <>
      <PageHeader eyebrow="Centre de commandement" title="Du triage N1 au threat hunting N3">
        Un parcours opérationnel avec de vrais Event IDs, de vraies requêtes et des tickets à résoudre. Votre progression reste dans ce navigateur.
      </PageHeader>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Card className="p-5">
          <div className="flex items-center gap-3">
            <Trophy size={28} className="text-amber" aria-hidden />
            <div>
              <p className="text-xl font-bold text-white">{rank.name}</p>
              <p className="font-mono text-sm text-mute">{xp} XP</p>
            </div>
          </div>
          <div className="mt-4">
            <ProgressBar value={ratio} tone="bg-emerald" label="Progression vers le rang suivant" />
          </div>
          <p className="mt-2 text-sm text-mute">{next ? `Encore ${next.min - xp} XP pour devenir ${next.name}.` : 'Vous avez atteint le rang maximal.'}</p>
          <ol className="mt-4 grid grid-cols-2 gap-2 sm:grid-cols-4">
            {RANKS.map((r) => (
              <li key={r.name} className={`rounded border px-2 py-1.5 text-xs ${r.name === rank.name ? 'border-emerald text-white' : xp >= r.min ? 'border-line text-ink' : 'border-line text-mute'}`}>
                {r.name}
                <span className="block font-mono text-[11px] text-mute">{r.min} XP</span>
              </li>
            ))}
          </ol>
        </Card>

        <Card className="flex flex-col p-5">
          <p className="font-mono text-xs tracking-widest text-cyan uppercase">Prochaine étape</p>
          <p className="mt-2 font-semibold text-white">{step.label}</p>
          <p className="mt-1 flex-1 text-sm text-mute">{step.detail}</p>
          <Link to={step.to} className={`${btnPrimary} mt-4 self-start`}>
            Continuer <ArrowRight size={15} aria-hidden />
          </Link>
        </Card>
      </div>

      <div className="mt-4 grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map((s) => (
          <Link key={s.label} to={s.to} className="rounded-lg border border-line bg-card p-4 transition hover:border-cyan">
            <s.icon size={18} className="text-cyan" aria-hidden />
            <p className="mt-2 font-mono text-2xl font-bold text-white">
              {s.value}
              <span className="text-base font-normal text-mute"> / {s.total}</span>
            </p>
            <p className="text-sm text-ink">{s.label}</p>
            <p className="text-xs text-mute">{s.sub}</p>
          </Link>
        ))}
      </div>

      <h2 className="mt-8 mb-3 text-lg font-semibold text-white">Parcours des modules</h2>
      <ol className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {modules.map((m) => {
          const read = progress.coursesRead[m.id]?.length ?? 0
          const quiz = progress.quizBest[m.id]
          return (
            <li key={m.id}>
              <Link to={`/modules/${m.id}`} className="block h-full rounded-lg border border-line bg-card p-4 transition hover:border-cyan">
                <div className="flex items-start gap-3">
                  <span className="font-mono text-xl font-bold text-cyan">{String(m.number).padStart(2, '0')}</span>
                  <div className="min-w-0 flex-1">
                    <p className="font-medium text-white">{m.title}</p>
                    <div className="my-2">
                      <ProgressBar value={read / m.sections.length} label={`Lecture du module ${m.number}`} />
                    </div>
                    <p className="text-xs text-mute">
                      {read}/{m.sections.length} sections · {quiz === undefined ? 'Quiz à faire' : `Quiz : ${quiz} %`} · {m.tier}
                    </p>
                  </div>
                </div>
              </Link>
            </li>
          )
        })}
      </ol>

      <div className="mt-8 text-right">
        <button
          type="button"
          className={btnGhost}
          onClick={() => {
            if (window.confirm('Effacer toute votre progression ? Cette action est définitive.')) reset()
          }}
        >
          <RotateCcw size={14} aria-hidden /> Réinitialiser ma progression
        </button>
      </div>
    </>
  )
}
