import { Database, Swords, TriangleAlert, X } from 'lucide-react'
import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Card, CodeBlock, PageHeader, Rich, Tag, inputCls } from '../components/ui'
import { MITRE_TACTICS, techniques } from '../data/mitre'
import type { Technique } from '../types'

function Detail({ technique, onClose }: { technique: Technique; onClose: () => void }) {
  return (
    <Card className="mb-5 border-cyan/60 p-4 sm:p-5">
      <div className="flex items-start justify-between gap-3">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <Tag className="text-cyan">{technique.id}</Tag>
            <Tag>{technique.tactic}</Tag>
          </div>
          <h2 className="mt-2 text-xl font-bold text-white">{technique.name}</h2>
        </div>
        <button type="button" onClick={onClose} aria-label="Fermer la technique" className="text-mute hover:text-white">
          <X size={20} />
        </button>
      </div>

      <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2">
        <section>
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-red-300">
            <Swords size={15} aria-hidden /> Comment l’attaquant procède
          </h3>
          <p className="mt-1 text-sm">
            <Rich text={technique.how} />
          </p>
        </section>
        <section>
          <h3 className="flex items-center gap-1.5 text-sm font-semibold text-cyan-300">
            <Database size={15} aria-hidden /> Quels logs le détectent
          </h3>
          <ul className="mt-1.5 flex flex-wrap gap-1.5">
            {technique.logs.map((log) => (
              <li key={log}>
                <Tag>{log}</Tag>
              </li>
            ))}
          </ul>
        </section>
      </div>

      <CodeBlock code={technique.kql} lang="kql" title="Chasse dans Microsoft Sentinel / Defender" />
      <CodeBlock code={technique.spl} lang="spl" title="Chasse dans Splunk" />

      <p className="flex gap-2 rounded-md border border-amber/40 bg-amber/5 p-3 text-sm">
        <TriangleAlert size={16} className="mt-0.5 shrink-0 text-amber" aria-hidden />
        <span>
          <strong className="font-semibold text-white">Faux positifs : </strong>
          <Rich text={technique.falsePositives} />
        </span>
      </p>
      <p className="mt-3 text-xs text-mute">Les noms d’index, de tables et de champs varient selon votre SIEM et vos connecteurs : adaptez avant d’utiliser.</p>
    </Card>
  )
}

export function MitreExplorer() {
  const [params, setParams] = useSearchParams()
  const selectedId = params.get('t')
  const filter = params.get('f') ?? ''
  const selected = techniques.find((t) => t.id === selectedId)

  const setParam = (key: string, value: string | null) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const visible = useMemo(() => {
    const f = filter.trim().toLowerCase()
    if (!f) return techniques
    return techniques.filter((t) => [t.id, t.name, t.how, ...t.logs].join(' ').toLowerCase().includes(f))
  }, [filter])

  return (
    <>
      <PageHeader eyebrow="Explorateur" title="MITRE ATT&CK opérationnel">
        {techniques.length} techniques courantes en entreprise, chacune avec la méthode de l’attaquant, les journaux utiles et la requête de chasse en KQL et SPL.
      </PageHeader>

      {selected && <Detail technique={selected} onClose={() => setParam('t', null)} />}

      <label htmlFor="mitre-filter" className="sr-only">
        Filtrer les techniques
      </label>
      <input id="mitre-filter" value={filter} onChange={(e) => setParam('f', e.target.value || null)} placeholder="Filtrer : LSASS, 4769, PsExec, DNS…" className={`${inputCls} mb-4 max-w-md`} />

      <div className="-mx-4 overflow-x-auto px-4 pb-3 sm:mx-0 sm:px-0">
        <div className="grid min-w-[62rem] grid-cols-8 gap-2">
          {MITRE_TACTICS.map((tactic) => {
            const items = visible.filter((t) => t.tactic === tactic)
            return (
              <section key={tactic} aria-label={tactic}>
                <h2 className="mb-2 flex min-h-12 items-center rounded-md border border-line bg-raised px-2 py-1.5 text-xs leading-tight font-semibold text-white">{tactic}</h2>
                <ul className="space-y-1.5">
                  {items.map((t) => (
                    <li key={t.id}>
                      <button
                        type="button"
                        aria-pressed={selectedId === t.id}
                        onClick={() => {
                          setParam('t', selectedId === t.id ? null : t.id)
                          window.scrollTo({ top: 0 })
                        }}
                        className={`w-full rounded-md border p-2 text-left transition ${selectedId === t.id ? 'border-cyan bg-cyan/10' : 'border-line bg-card hover:border-cyan'}`}
                      >
                        <span className="block font-mono text-[11px] text-cyan">{t.id}</span>
                        <span className="block text-xs leading-snug text-ink">{t.name}</span>
                      </button>
                    </li>
                  ))}
                  {!items.length && <li className="px-2 text-xs text-mute">Aucune</li>}
                </ul>
              </section>
            )
          })}
        </div>
      </div>
    </>
  )
}
