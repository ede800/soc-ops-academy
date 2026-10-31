import { Download, Eraser } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Card, CodeBlock, CopyButton, PageHeader, btnGhost, btnPrimary, inputCls } from '../components/ui'
import { techniques } from '../data/mitre'
import { siemAlerts } from '../data/siemAlerts'
import { defang, extractIocs } from '../lib/forensics'
import { parseModelReport } from '../lib/scoring'

const KEY = 'soc-ops-academy.report.v1'

interface Draft {
  id: string
  title: string
  analyst: string
  severity: string
  verdict: string
  tlp: string
  qui: string
  quoi: string
  quand: string
  ou: string
  pourquoi: string
  timeline: string
  iocSource: string
  mitre: string[]
  actions: string
  recommendations: string
}

const EMPTY: Draft = {
  id: '',
  title: '',
  analyst: '',
  severity: 'Haute',
  verdict: 'Vrai positif (TP)',
  tlp: 'TLP:AMBER',
  qui: '',
  quoi: '',
  quand: '',
  ou: '',
  pourquoi: '',
  timeline: '',
  iocSource: '',
  mitre: [],
  actions: '',
  recommendations: '',
}

function loadDraft(): Draft {
  try {
    const raw = localStorage.getItem(KEY)
    return raw ? { ...EMPTY, ...JSON.parse(raw) } : EMPTY
  } catch {
    return EMPTY
  }
}

const bullets = (text: string) =>
  text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .map((l) => `- ${l.replace(/^[-*]\s*/, '')}`)
    .join('\n')

/** Une cellule Markdown tient sur une ligne, et un « | » de commande (curl|sh) ne doit pas créer une colonne. */
const cell = (text: string) => text.trim().replace(/\|/g, '\\|').replace(/\s*\n\s*/g, '<br>') || '-'

export function buildMarkdown(d: Draft): string {
  const iocs = extractIocs(d.iocSource)
  const iocLines = [
    ...iocs.urls.map((v) => `| URL | \`${defang(v)}\` |`),
    ...iocs.domains.map((v) => `| Domaine | \`${defang(v)}\` |`),
    ...iocs.ipv4.map((v) => `| IPv4 | \`${defang(v)}\` |`),
    ...iocs.emails.map((v) => `| Email | \`${defang(v)}\` |`),
    ...iocs.sha256.map((v) => `| SHA-256 | \`${v}\` |`),
    ...iocs.sha1.map((v) => `| SHA-1 | \`${v}\` |`),
    ...iocs.md5.map((v) => `| MD5 | \`${v}\` |`),
    ...iocs.cves.map((v) => `| CVE | \`${v}\` |`),
  ]
  const mitre = d.mitre.map((id) => {
    const t = techniques.find((x) => x.id === id)
    return `- ${id} : ${t?.name ?? ''} (${t?.tactic ?? ''})`
  })
  return `# Rapport d'incident ${d.id || '[ID]'} : ${d.title || '[Titre]'}

**${d.tlp}** | **Sévérité :** ${d.severity} | **Verdict :** ${d.verdict} | **Analyste :** ${d.analyst || '[Nom]'}

## Synthèse

| | |
|---|---|
| **Qui** | ${cell(d.qui)} |
| **Quoi** | ${cell(d.quoi)} |
| **Quand** | ${cell(d.quand)} |
| **Où** | ${cell(d.ou)} |
| **Pourquoi** | ${cell(d.pourquoi)} |

## Chronologie (UTC)

${bullets(d.timeline) || '- À compléter'}

## Indicateurs de compromission

${iocLines.length ? `| Type | Valeur |\n|---|---|\n${iocLines.join('\n')}` : 'Aucun indicateur extrait.'}

## MITRE ATT&CK

${mitre.join('\n') || '- À compléter'}

## Actions réalisées

${bullets(d.actions) || '- À compléter'}

## Recommandations

${bullets(d.recommendations) || '- À compléter'}
`
}

const TEXT_FIELDS: { key: keyof Draft; label: string; rows: number; hint?: string }[] = [
  { key: 'qui', label: 'Qui', rows: 2 },
  { key: 'quoi', label: 'Quoi', rows: 3 },
  { key: 'quand', label: 'Quand', rows: 1 },
  { key: 'ou', label: 'Où', rows: 2 },
  { key: 'pourquoi', label: 'Pourquoi', rows: 3 },
  { key: 'timeline', label: 'Chronologie', rows: 4, hint: 'Un événement par ligne' },
  { key: 'iocSource', label: 'Texte source des IOC', rows: 4, hint: 'Collez des logs : les IOC sont extraits et défangés automatiquement' },
  { key: 'actions', label: 'Actions réalisées', rows: 3, hint: 'Une action par ligne' },
  { key: 'recommendations', label: 'Recommandations', rows: 3, hint: 'Une recommandation par ligne' },
]

export function ReportGenerator() {
  const [draft, setDraft] = useState<Draft>(loadDraft)
  const markdown = useMemo(() => buildMarkdown(draft), [draft])

  useEffect(() => {
    try {
      localStorage.setItem(KEY, JSON.stringify(draft))
    } catch {
      // Brouillon conservé en mémoire seulement.
    }
  }, [draft])

  const set = <K extends keyof Draft>(key: K, value: Draft[K]) => setDraft((d) => ({ ...d, [key]: value }))

  const prefill = (alertId: string) => {
    const a = siemAlerts.find((x) => x.id === alertId)
    if (!a) return
    const dirty = JSON.stringify({ ...draft, analyst: '' }) !== JSON.stringify(EMPTY)
    if (dirty && !window.confirm('Remplacer le brouillon en cours par ce ticket ?')) return
    const parsed = parseModelReport(a.solution.modelReport)
    setDraft({
      ...EMPTY,
      analyst: draft.analyst,
      id: a.id,
      title: a.title,
      severity: a.severity,
      verdict: { TP: 'Vrai positif (TP)', FP: 'Faux positif (FP)', 'B-TP': 'Vrai positif bénin (B-TP)' }[a.solution.classification],
      qui: parsed.qui,
      quoi: parsed.quoi,
      quand: parsed.quand,
      ou: parsed.ou,
      pourquoi: parsed.pourquoi,
      actions: parsed.verdict,
      iocSource: [...a.intel.filter((i) => i.type !== 'Compte' && i.type !== 'Contexte').map((i) => i.value)].join('\n'),
    })
  }

  const download = () => {
    const url = URL.createObjectURL(new Blob([markdown], { type: 'text/markdown;charset=utf-8' }))
    const link = document.createElement('a')
    link.href = url
    link.download = `rapport-${(draft.id || 'incident').toLowerCase()}.md`
    link.click()
    URL.revokeObjectURL(url)
  }

  return (
    <>
      <PageHeader eyebrow="Générateur" title="Rapport d’incident">
        Remplissez le formulaire : le rapport Markdown se met à jour en direct. Votre brouillon reste dans ce navigateur.
      </PageHeader>

      <div className="grid grid-cols-1 items-start gap-5 xl:grid-cols-2">
        <Card className="space-y-3 p-4 sm:p-5">
          <div>
            <label htmlFor="prefill" className="mb-1 block text-sm">
              Partir d’un ticket du simulateur <span className="text-xs text-mute">· contient le corrigé du ticket</span>
            </label>
            <select id="prefill" value="" onChange={(e) => prefill(e.target.value)} className={inputCls}>
              <option value="">Choisir un ticket pour préremplir…</option>
              {siemAlerts.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.id} : {a.title}
                </option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div>
              <label htmlFor="r-id" className="mb-1 block text-sm">Référence</label>
              <input id="r-id" value={draft.id} onChange={(e) => set('id', e.target.value)} className={inputCls} placeholder="INC-20418" />
            </div>
            <div>
              <label htmlFor="r-analyst" className="mb-1 block text-sm">Analyste</label>
              <input id="r-analyst" value={draft.analyst} onChange={(e) => set('analyst', e.target.value)} className={inputCls} />
            </div>
          </div>
          <div>
            <label htmlFor="r-title" className="mb-1 block text-sm">Titre</label>
            <input id="r-title" value={draft.title} onChange={(e) => set('title', e.target.value)} className={inputCls} />
          </div>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            <div>
              <label htmlFor="r-sev" className="mb-1 block text-sm">Sévérité</label>
              <select id="r-sev" value={draft.severity} onChange={(e) => set('severity', e.target.value)} className={inputCls}>
                {['Critique', 'Haute', 'Moyenne', 'Basse'].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label htmlFor="r-verdict" className="mb-1 block text-sm">Verdict</label>
              <select id="r-verdict" value={draft.verdict} onChange={(e) => set('verdict', e.target.value)} className={inputCls}>
                {['Vrai positif (TP)', 'Faux positif (FP)', 'Vrai positif bénin (B-TP)'].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
            <div>
              <label htmlFor="r-tlp" className="mb-1 block text-sm">Diffusion</label>
              <select id="r-tlp" value={draft.tlp} onChange={(e) => set('tlp', e.target.value)} className={inputCls}>
                {['TLP:RED', 'TLP:AMBER+STRICT', 'TLP:AMBER', 'TLP:GREEN', 'TLP:CLEAR'].map((s) => <option key={s}>{s}</option>)}
              </select>
            </div>
          </div>

          {TEXT_FIELDS.map((f) => (
            <div key={f.key}>
              <label htmlFor={`r-${f.key}`} className="mb-1 block text-sm">
                {f.label} {f.hint && <span className="text-xs text-mute">· {f.hint}</span>}
              </label>
              <textarea id={`r-${f.key}`} rows={f.rows} value={draft[f.key] as string} onChange={(e) => set(f.key, e.target.value as never)} className={`${inputCls} font-mono text-[13px]`} />
            </div>
          ))}

          <div>
            <label htmlFor="r-mitre" className="mb-1 block text-sm">
              Techniques MITRE <span className="text-xs text-mute">· Ctrl+clic pour en sélectionner plusieurs</span>
            </label>
            <select
              id="r-mitre"
              multiple
              size={6}
              value={draft.mitre}
              onChange={(e) => set('mitre', Array.from(e.target.selectedOptions, (o) => o.value))}
              className={`${inputCls} font-mono text-xs`}
            >
              {techniques.map((t) => (
                <option key={t.id} value={t.id}>
                  {t.id} · {t.name}
                </option>
              ))}
            </select>
          </div>

          <button
            type="button"
            className={btnGhost}
            onClick={() => {
              if (window.confirm('Effacer le brouillon de rapport ?')) setDraft(EMPTY)
            }}
          >
            <Eraser size={14} aria-hidden /> Effacer le brouillon
          </button>
        </Card>

        <div className="xl:sticky xl:top-6">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <h2 className="font-semibold text-white">Aperçu Markdown</h2>
            <div className="flex items-center gap-2">
              <CopyButton text={markdown} />
              <button type="button" onClick={download} className={btnPrimary}>
                <Download size={14} aria-hidden /> Télécharger .md
              </button>
            </div>
          </div>
          <div className="xl:max-h-[80vh] xl:overflow-y-auto">
            <CodeBlock code={markdown} lang="text" title="rapport.md" />
          </div>
        </div>
      </div>
    </>
  )
}
