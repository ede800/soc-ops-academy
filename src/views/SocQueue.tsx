import { ArrowLeft, ArrowRight, CheckCircle2, CircleDashed, Clock, Lock, MinusCircle, RotateCcw, Send, Server, ShieldAlert, User, XCircle } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { Link, Navigate, useParams } from 'react-router-dom'
import { ProcessTree } from '../components/ProcessTree'
import { Card, CodeBlock, CopyButton, PageHeader, Rich, SeverityBadge, Tag, btnGhost, btnPrimary, inputCls } from '../components/ui'
import { CONTAINMENT_ACTIONS, TACTICS, siemAlerts } from '../data/siemAlerts'
import { loadTicketDraft, saveTicketDraft, useProgress } from '../lib/progress'
import { EMPTY_REPORT, REPORT_LABELS, scoreDecision, type ReportFields, type ScoreDetail } from '../lib/scoring'
import type { IntelItem, SiemAlert } from '../types'

export function SocQueue() {
  const { progress } = useProgress()
  const open = siemAlerts.filter((a) => progress.alerts[a.id] === undefined).length
  return (
    <>
      <PageHeader eyebrow="Simulateur" title="Live SOC Queue">
        {open} tickets sur {siemAlerts.length} en attente. Comme en production, le titre ne dit pas la vérité : certains sont critiques, d’autres n’ont aucune gravité. Inspectez les preuves, décidez, documentez.
      </PageHeader>
      <Card className="overflow-hidden">
        <ul>
          {siemAlerts.map((a) => {
            const score = progress.alerts[a.id]
            return (
              <li key={a.id} className="border-b border-line last:border-b-0">
                <Link to={`/soc-queue/${a.id}`} className="flex flex-wrap items-center gap-x-4 gap-y-1.5 p-4 transition hover:bg-raised">
                  <SeverityBadge severity={a.severity} />
                  <div className="min-w-0 flex-1 basis-64">
                    <p className="font-medium text-white">{a.title}</p>
                    <p className="font-mono text-xs text-mute">
                      {a.id} · {a.source} · {a.host}
                    </p>
                  </div>
                  <span className="font-mono text-xs text-mute">{a.time}</span>
                  {score === undefined ? (
                    <span className="flex w-24 items-center gap-1 text-xs text-amber-300">
                      <CircleDashed size={14} aria-hidden /> Ouvert
                    </span>
                  ) : (
                    <span className="flex w-24 items-center gap-1 text-xs text-emerald-300">
                      <CheckCircle2 size={14} aria-hidden /> {score}/100
                    </span>
                  )}
                </Link>
              </li>
            )
          })}
        </ul>
      </Card>
    </>
  )
}

const VERDICT_CLS: Record<IntelItem['verdict'], string> = {
  Malveillant: 'border-crimson/60 text-red-300',
  Suspect: 'border-amber/60 text-amber-300',
  Légitime: 'border-emerald/60 text-emerald-300',
  Inconnu: 'border-line text-mute',
}

type EvidenceTab = 'logs' | 'tree' | 'intel'

function Evidence({ alert }: { alert: SiemAlert }) {
  const [tab, setTab] = useState<EvidenceTab>('logs')
  const tabs: { id: EvidenceTab; label: string }[] = [
    { id: 'logs', label: `Logs bruts (${alert.logs.length})` },
    ...(alert.tree ? [{ id: 'tree' as const, label: 'Arbre de processus' }] : []),
    { id: 'intel', label: `Threat Intel (${alert.intel.length})` },
  ]
  return (
    <section aria-label="Preuves">
      <div role="tablist" className="flex gap-1 overflow-x-auto border-b border-line">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tab === t.id}
            onClick={() => setTab(t.id)}
            className={`-mb-px shrink-0 border-b-2 px-3 py-2 text-sm ${tab === t.id ? 'border-cyan font-medium text-white' : 'border-transparent text-mute hover:text-white'}`}
          >
            {t.label}
          </button>
        ))}
      </div>
      <div className="pt-1">
        {tab === 'logs' && alert.logs.map((log) => <CodeBlock key={log.title} code={log.content} lang={log.lang} title={log.title} />)}
        {tab === 'tree' && alert.tree && (
          <div className="pt-3">
            {alert.treeNote && <p className="mb-3 text-sm text-mute">{alert.treeNote}</p>}
            <ProcessTree tree={alert.tree} />
          </div>
        )}
        {tab === 'intel' && (
          <ul className="space-y-2 pt-3">
            {alert.intel.map((item) => (
              <li key={item.value} className="rounded-md border border-line bg-bg p-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Tag>{item.type}</Tag>
                  <code className="min-w-0 font-mono text-xs break-all text-white">{item.value}</code>
                  <span className={`ml-auto rounded border px-1.5 py-0.5 text-xs ${VERDICT_CLS[item.verdict]}`}>{item.verdict}</span>
                </div>
                <p className="mt-1.5 text-sm text-mute">{item.detail}</p>
              </li>
            ))}
            <li className="text-xs text-mute">Enrichissement simulé : les IP et domaines appartiennent à des plages réservées à la documentation.</li>
          </ul>
        )}
      </div>
    </section>
  )
}

function Line({ ok, partial, label, points, max, children }: { ok: boolean; partial?: boolean; label: string; points: number; max: number; children?: ReactNode }) {
  const Icon = ok ? CheckCircle2 : partial ? MinusCircle : XCircle
  const cls = ok ? 'text-emerald' : partial ? 'text-amber' : 'text-crimson'
  return (
    <li className="flex gap-2.5 border-t border-line py-2.5 first:border-t-0">
      <Icon size={18} className={`mt-0.5 shrink-0 ${cls}`} aria-hidden />
      <div className="min-w-0 flex-1 text-sm">
        <div className="flex justify-between gap-2">
          <span className="font-medium text-white">{label}</span>
          <span className="font-mono text-mute">
            {points}/{max}
          </span>
        </div>
        {children}
      </div>
    </li>
  )
}

function actionLabel(id: string) {
  return CONTAINMENT_ACTIONS.find((a) => a.id === id)?.label ?? id
}

const CLASS_LABEL: Record<string, string> = { TP: 'Vrai positif (TP)', FP: 'Faux positif (FP)', 'B-TP': 'Vrai positif bénin (B-TP)' }

function Feedback({ alert, score, onRetry }: { alert: SiemAlert; score: ScoreDetail; onRetry: () => void }) {
  const s = alert.solution
  const index = siemAlerts.indexOf(alert)
  const next = siemAlerts[index + 1]
  const tone = score.total >= 80 ? 'text-emerald' : score.total >= 50 ? 'text-amber' : 'text-crimson'
  return (
    <section aria-live="polite" className="space-y-4">
      <Card className="p-5">
        <div className="flex items-baseline justify-between gap-3">
          <h2 className="font-semibold text-white">Correction</h2>
          <p className={`font-mono text-3xl font-bold ${tone}`}>
            {score.total}
            <span className="text-base font-normal text-mute">/100</span>
          </p>
        </div>
        <ul className="mt-2">
          <Line ok={score.classification.ok} label="Classification" points={score.classification.points} max={40}>
            <p className="text-mute">Attendu : {CLASS_LABEL[s.classification]}</p>
          </Line>
          <Line ok={score.tactic.ok} label="Tactique MITRE ATT&CK" points={score.tactic.points} max={15}>
            <p className="text-mute">Attendu : {s.tactics.join(' ou ')}</p>
          </Line>
          <Line ok={score.action.ok} partial={score.action.partial} label="Action de confinement" points={score.action.points} max={20}>
            <p className="text-mute">
              {score.action.partial && 'Utile, mais insuffisant en premier. '}
              Attendu : {s.actions.map(actionLabel).join(' ou ')}
            </p>
          </Line>
          <Line ok={score.report.points >= 20} partial={score.report.points >= 10} label="Rapport d’investigation" points={score.report.points} max={25}>
            {score.report.verdictConflict && <p className="text-red-300">Votre verdict écrit contredit la classification choisie (5 points de moins).</p>}
            {score.report.missingFields.length > 0 && <p className="text-red-300">Champs vides : {score.report.missingFields.join(', ')}</p>}
            {score.report.thinFields.length > 0 && <p className="text-amber-300">Trop courts : {score.report.thinFields.join(', ')}</p>}
            {score.report.keywordsFound.length > 0 && <p className="text-emerald-300">Preuves citées : {score.report.keywordsFound.join(' · ')}</p>}
            {score.report.keywordsMissing.length > 0 && <p className="text-mute">Preuves manquantes : {score.report.keywordsMissing.join(' · ')}</p>}
          </Line>
        </ul>
        <p className="mt-2 text-xs text-mute">Le rapport est corrigé automatiquement sur sa structure et la présence des preuves attendues. Comparez-le aussi au rapport modèle.</p>
      </Card>

      <Card className="p-5 text-sm">
        <h3 className="font-semibold text-white">Analyse de l’expert</h3>
        <p className="mt-2">
          <Rich text={s.debrief} />
        </p>
        <h3 className="mt-4 flex items-center gap-1.5 font-semibold text-amber-300">
          <ShieldAlert size={15} aria-hidden /> Le piège
        </h3>
        <p className="mt-1">
          <Rich text={s.pitfall} />
        </p>
      </Card>

      <Card className="p-5">
        <div className="flex items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-white">Rapport modèle</h3>
          <CopyButton text={s.modelReport} />
        </div>
        <pre className="mt-2 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-slate-300">{s.modelReport}</pre>
      </Card>

      <div className="flex flex-wrap gap-2">
        <button type="button" onClick={onRetry} className={btnGhost}>
          <RotateCcw size={14} aria-hidden /> Rejouer ce ticket
        </button>
        {next ? (
          <Link to={`/soc-queue/${next.id}`} className={btnPrimary}>
            Ticket suivant <ArrowRight size={14} aria-hidden />
          </Link>
        ) : (
          <Link to="/soc-queue" className={btnPrimary}>
            Retour à la file
          </Link>
        )}
      </div>
    </section>
  )
}

function readDraft(alertId: string) {
  const raw = loadTicketDraft(alertId)
  const o = (typeof raw === 'object' && raw !== null ? raw : {}) as Record<string, unknown>
  const text = (v: unknown) => (typeof v === 'string' ? v : '')
  const rep = (typeof o.report === 'object' && o.report !== null ? o.report : {}) as Record<string, unknown>
  const report = { ...EMPTY_REPORT }
  for (const key of Object.keys(REPORT_LABELS) as (keyof ReportFields)[]) report[key] = text(rep[key])
  return { classification: text(o.classification), tactic: text(o.tactic), action: text(o.action), report }
}

function DecisionForm({ alert, onSubmit }: { alert: SiemAlert; onSubmit: (score: ScoreDetail) => void }) {
  const [draft] = useState(() => readDraft(alert.id))
  const [classification, setClassification] = useState(draft.classification)
  const [tactic, setTactic] = useState(draft.tactic)
  const [action, setAction] = useState(draft.action)
  const [report, setReport] = useState<ReportFields>(draft.report)
  const ready = classification && tactic && action

  useEffect(() => {
    saveTicketDraft(alert.id, { classification, tactic, action, report })
  }, [alert.id, classification, tactic, action, report])

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault()
        onSubmit(scoreDecision(alert, { classification, tactic, action, report }))
      }}
      className="space-y-5"
    >
      <fieldset>
        <legend className="mb-2 text-sm font-semibold text-white">1. Classification</legend>
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
          {Object.entries(CLASS_LABEL).map(([id, label]) => (
            <label key={id} className={`cursor-pointer rounded-md border p-2.5 text-center text-sm transition ${classification === id ? 'border-cyan bg-cyan/10 text-white' : 'border-line hover:border-cyan'}`}>
              <input type="radio" name="classification" value={id} checked={classification === id} onChange={() => setClassification(id)} className="sr-only" />
              {label}
            </label>
          ))}
        </div>
      </fieldset>

      <div>
        <label htmlFor="tactic" className="mb-2 block text-sm font-semibold text-white">
          2. Tactique MITRE ATT&CK
        </label>
        <select id="tactic" value={tactic} onChange={(e) => setTactic(e.target.value)} className={inputCls}>
          <option value="">Sélectionnez une tactique…</option>
          {TACTICS.map((t) => (
            <option key={t}>{t}</option>
          ))}
        </select>
      </div>

      <div>
        <label htmlFor="action" className="mb-2 block text-sm font-semibold text-white">
          3. Action de confinement prioritaire
        </label>
        <select id="action" value={action} onChange={(e) => setAction(e.target.value)} className={inputCls}>
          <option value="">Sélectionnez une action…</option>
          {CONTAINMENT_ACTIONS.map((a) => (
            <option key={a.id} value={a.id}>
              {a.label}
            </option>
          ))}
        </select>
      </div>

      <fieldset>
        <legend className="mb-2 text-sm font-semibold text-white">4. Rapport d’investigation</legend>
        <div className="space-y-3">
          {(Object.keys(REPORT_LABELS) as (keyof ReportFields)[]).map((key) => (
            <div key={key}>
              <label htmlFor={`rep-${key}`} className="mb-1 block text-sm">
                {REPORT_LABELS[key].label} <span className="text-xs text-mute">· {REPORT_LABELS[key].hint}</span>
              </label>
              <textarea id={`rep-${key}`} rows={2} value={report[key]} onChange={(e) => setReport({ ...report, [key]: e.target.value })} className={`${inputCls} font-mono text-[13px]`} />
            </div>
          ))}
        </div>
      </fieldset>

      <button type="submit" disabled={!ready} className={`${btnPrimary} w-full`}>
        <Send size={15} aria-hidden /> Clôturer et obtenir la correction
      </button>
      {!ready && (
        <p className="flex items-center justify-center gap-1.5 text-xs text-mute">
          <Lock size={12} aria-hidden /> Choisissez une classification, une tactique et une action pour clôturer.
        </p>
      )}
    </form>
  )
}

export function SocTicket() {
  const { id } = useParams()
  const alert = siemAlerts.find((a) => a.id === id)
  if (!alert) return <Navigate to="/soc-queue" replace />
  return <Ticket key={alert.id} alert={alert} />
}

function Ticket({ alert }: { alert: SiemAlert }) {
  const { progress, saveAlert } = useProgress()
  const [score, setScore] = useState<ScoreDetail | null>(null)
  const best = progress.alerts[alert.id]
  const panelRef = useRef<HTMLDivElement>(null)

  // Le formulaire est plus long que la correction : sans cela, on atterrit au milieu sur mobile.
  useEffect(() => {
    if (score) panelRef.current?.scrollIntoView({ block: 'start' })
  }, [score])

  return (
    <>
      <Link to="/soc-queue" className="mb-3 inline-flex items-center gap-1 text-sm text-mute hover:text-white">
        <ArrowLeft size={14} aria-hidden /> File d’alertes
      </Link>
      <header className="mb-5">
        <div className="flex flex-wrap items-center gap-2">
          <SeverityBadge severity={alert.severity} />
          <Tag>{alert.id}</Tag>
          <Tag>{alert.source}</Tag>
          {best !== undefined && <span className="text-xs text-mute">Meilleur score : {best}/100</span>}
        </div>
        <h1 className="mt-2 text-2xl font-bold text-white">{alert.title}</h1>
        <p className="mt-1 max-w-3xl text-mute">{alert.summary}</p>
        <dl className="mt-3 flex flex-wrap gap-x-5 gap-y-1 font-mono text-xs text-mute">
          <div className="flex items-center gap-1.5">
            <Clock size={13} aria-hidden />
            <dt className="sr-only">Heure</dt>
            <dd>{alert.time}</dd>
          </div>
          <div className="flex items-center gap-1.5">
            <Server size={13} aria-hidden />
            <dt className="sr-only">Hôte</dt>
            <dd>{alert.host}</dd>
          </div>
          <div className="flex items-center gap-1.5">
            <User size={13} aria-hidden />
            <dt className="sr-only">Compte</dt>
            <dd>{alert.user}</dd>
          </div>
        </dl>
        <p className="mt-2 font-mono text-xs break-all text-mute">Règle : {alert.rule}</p>
      </header>

      <div className="grid grid-cols-1 items-start gap-6 xl:grid-cols-[minmax(0,3fr)_minmax(0,2fr)]">
        <Evidence alert={alert} />
        <div ref={panelRef} className="scroll-mt-16 xl:sticky xl:top-6">
          {score ? (
            <Feedback alert={alert} score={score} onRetry={() => setScore(null)} />
          ) : (
            <Card className="p-5">
              <DecisionForm
                alert={alert}
                onSubmit={(result) => {
                  setScore(result)
                  saveAlert(alert.id, result.total)
                }}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  )
}
