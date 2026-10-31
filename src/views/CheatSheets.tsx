import { useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Card, PageHeader, Rich, inputCls } from '../components/ui'
import { CHEAT_CATEGORIES, cheatEntries } from '../data/cheatSheets'

export function CheatSheets() {
  const [params, setParams] = useSearchParams()
  const q = params.get('q') ?? ''
  const category = params.get('c') ?? ''

  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params)
    if (value) next.set(key, value)
    else next.delete(key)
    setParams(next, { replace: true })
  }

  const rows = useMemo(() => {
    const f = q.trim().toLowerCase()
    return cheatEntries.filter(
      (e) => (!category || e.category === category) && (!f || [e.id, e.title, e.meaning, e.malicious].join(' ').toLowerCase().includes(f)),
    )
  }, [q, category])

  return (
    <>
      <PageHeader eyebrow="Référence" title="Cheat sheets de terrain">
        {cheatEntries.length} entrées : ce que signifie chaque identifiant et quand il devient malveillant. Accessible depuis n’importe quelle page avec Ctrl+K.
      </PageHeader>

      <label htmlFor="cheat-filter" className="sr-only">
        Filtrer les entrées
      </label>
      <input id="cheat-filter" value={q} onChange={(e) => update('q', e.target.value)} placeholder="Filtrer : 4769, certutil, 445…" className={`${inputCls} max-w-md font-mono`} />

      <div className="my-4 flex flex-wrap gap-1.5">
        {['', ...CHEAT_CATEGORIES].map((c) => (
          <button
            key={c || 'all'}
            type="button"
            aria-pressed={category === c}
            onClick={() => update('c', c)}
            className={`rounded-md border px-2.5 py-1 text-xs ${category === c ? 'border-cyan bg-cyan/10 text-white' : 'border-line text-mute hover:text-white'}`}
          >
            {c || 'Toutes'}
          </button>
        ))}
      </div>

      <p className="mb-2 text-sm text-mute" aria-live="polite">
        {rows.length} résultat{rows.length > 1 ? 's' : ''}
      </p>

      <Card className="overflow-x-auto">
        <table className="w-full min-w-[46rem] border-collapse text-left text-sm">
          <thead className="bg-raised text-xs tracking-wide text-mute uppercase">
            <tr>
              <th scope="col" className="w-32 px-3 py-2">Identifiant</th>
              <th scope="col" className="w-56 px-3 py-2">Nom</th>
              <th scope="col" className="px-3 py-2">Signification</th>
              <th scope="col" className="px-3 py-2 text-red-300">Quand est-ce malveillant ?</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e) => (
              <tr key={`${e.category}-${e.id}`} className="border-t border-line align-top">
                <td className="px-3 py-2 font-mono font-bold whitespace-nowrap text-white">{e.id}</td>
                <td className="px-3 py-2">
                  {e.title}
                  <span className="block text-xs text-mute">{e.category}</span>
                </td>
                <td className="px-3 py-2">
                  <Rich text={e.meaning} />
                </td>
                <td className="px-3 py-2">
                  <Rich text={e.malicious} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </Card>
    </>
  )
}
