import { ArrowLeft, CheckCircle2, GitBranch, ListChecks, OctagonAlert, Timer, Users } from 'lucide-react'
import { Link, Navigate, useParams } from 'react-router-dom'
import { Card, CodeBlock, PageHeader, ProgressBar, Rich, SeverityBadge, Tag } from '../components/ui'
import { playbooks } from '../data/playbooks'
import { useProgress } from '../lib/progress'
import { totals } from '../lib/totals'

export function PlaybooksList() {
  const { progress } = useProgress()
  return (
    <>
      <PageHeader eyebrow="Bibliothèque" title="Playbooks de réponse à incident">
        Cinq procédures complètes, de l’identification à la clôture, avec les commandes exactes. Cochez les étapes pendant que vous les étudiez ou que vous les appliquez en exercice.
      </PageHeader>
      <ul className="grid grid-cols-1 gap-3 md:grid-cols-2">
        {playbooks.map((b) => {
          const done = progress.playbookSteps[b.id]?.length ?? 0
          const total = totals.stepsByPlaybook[b.id]
          return (
            <li key={b.id}>
              <Link to={`/playbooks/${b.id}`} className="flex h-full flex-col rounded-lg border border-line bg-card p-5 transition hover:border-cyan">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={b.severity} />
                  <span className="text-xs text-mute">{b.sla}</span>
                </div>
                <h2 className="mt-2 flex-1 font-semibold text-white">{b.title}</h2>
                <div className="mt-3">
                  <ProgressBar value={done / total} tone={done >= total ? 'bg-emerald' : 'bg-cyan'} label={`Progression du playbook ${b.title}`} />
                </div>
                <p className="mt-1.5 text-xs text-mute">
                  {done}/{total} étapes · {b.phases.length} phases
                </p>
              </Link>
            </li>
          )
        })}
      </ul>
    </>
  )
}

export function PlaybookDetail() {
  const { id } = useParams()
  const { progress, toggleStep } = useProgress()
  const book = playbooks.find((b) => b.id === id)
  if (!book) return <Navigate to="/playbooks" replace />

  const checked = progress.playbookSteps[book.id] ?? []
  const total = totals.stepsByPlaybook[book.id]

  return (
    <>
      <Link to="/playbooks" className="mb-3 inline-flex items-center gap-1 text-sm text-mute hover:text-white">
        <ArrowLeft size={14} aria-hidden /> Tous les playbooks
      </Link>
      <PageHeader title={book.title} />

      <Card className="mb-5 grid grid-cols-1 gap-3 p-4 text-sm md:grid-cols-2">
        <p className="flex gap-2">
          <OctagonAlert size={16} className="mt-0.5 shrink-0 text-crimson" aria-hidden />
          <span>
            <strong className="font-semibold text-white">Déclencheur : </strong>
            {book.trigger}
          </span>
        </p>
        <p className="flex gap-2">
          <Users size={16} className="mt-0.5 shrink-0 text-cyan" aria-hidden />
          <span>
            <strong className="font-semibold text-white">Rôles : </strong>
            {book.roles}
          </span>
        </p>
        <p className="flex gap-2">
          <Timer size={16} className="mt-0.5 shrink-0 text-amber" aria-hidden />
          <span>
            <strong className="font-semibold text-white">Délai cible : </strong>
            {book.sla}
          </span>
        </p>
        <div className="flex flex-wrap items-center gap-1.5">
          <SeverityBadge severity={book.severity} />
          {book.mitre.map((m) => (
            <Tag key={m}>{m}</Tag>
          ))}
        </div>
      </Card>

      <div className="sticky top-12 z-20 mb-5 rounded-md border border-line bg-card/95 p-3 backdrop-blur lg:top-2">
        <div className="mb-1.5 flex justify-between text-xs text-mute">
          <span>Avancement</span>
          <span className="font-mono">
            {checked.length}/{total}
          </span>
        </div>
        <ProgressBar value={checked.length / total} tone={checked.length >= total ? 'bg-emerald' : 'bg-cyan'} label="Avancement du playbook" />
      </div>

      <ol className="space-y-6">
        {book.phases.map((phase, phaseIndex) => (
          <li key={phase.name}>
            <h2 className="mb-3 flex items-center gap-2 text-lg font-bold text-white">
              <span className="flex size-7 items-center justify-center rounded-full border border-cyan font-mono text-sm text-cyan">{phaseIndex + 1}</span>
              {phase.name}
            </h2>
            <ul className="space-y-3">
              {phase.steps.map((step, stepIndex) => {
                const stepId = `${phaseIndex}-${stepIndex}`
                const isDone = checked.includes(stepId)
                return (
                  <li key={stepId}>
                    <Card className={`p-4 ${isDone ? 'border-emerald/50' : ''}`}>
                      <label className="flex cursor-pointer items-start gap-3">
                        <input type="checkbox" checked={isDone} onChange={() => toggleStep(book.id, stepId)} className="mt-1 size-4 shrink-0 accent-emerald-500" />
                        <span>
                          <span className={`font-semibold ${isDone ? 'text-emerald-300' : 'text-white'}`}>{step.title}</span>
                          <span className="mt-1 block text-sm">
                            <Rich text={step.detail} />
                          </span>
                        </span>
                      </label>
                      {step.code && <CodeBlock code={step.code.code} lang={step.code.lang} title={step.code.title} />}
                      {step.decision && (
                        <p className="mt-3 flex gap-2 rounded-md border border-amber/50 bg-amber/5 p-3 text-sm">
                          <GitBranch size={16} className="mt-0.5 shrink-0 text-amber" aria-hidden />
                          <span>
                            <strong className="font-semibold text-white">Point de décision : </strong>
                            <Rich text={step.decision} />
                          </span>
                        </p>
                      )}
                    </Card>
                  </li>
                )
              })}
            </ul>
          </li>
        ))}
      </ol>

      <div className="mt-8 grid grid-cols-1 gap-4 md:grid-cols-2">
        <Card className="p-4">
          <h2 className="flex items-center gap-2 font-semibold text-white">
            <ListChecks size={17} className="text-emerald" aria-hidden /> Critères de clôture
          </h2>
          <ul className="mt-2 space-y-1.5 text-sm">
            {book.closure.map((c) => (
              <li key={c} className="flex gap-2">
                <CheckCircle2 size={15} className="mt-0.5 shrink-0 text-emerald" aria-hidden /> {c}
              </li>
            ))}
          </ul>
        </Card>
        <Card className="p-4">
          <h2 className="flex items-center gap-2 font-semibold text-white">
            <OctagonAlert size={17} className="text-crimson" aria-hidden /> Erreurs fréquentes
          </h2>
          <ul className="mt-2 list-disc space-y-1.5 pl-5 text-sm marker:text-crimson">
            {book.pitfalls.map((c) => (
              <li key={c}>
                <Rich text={c} />
              </li>
            ))}
          </ul>
        </Card>
      </div>
    </>
  )
}
