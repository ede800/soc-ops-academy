import { CornerDownLeft, Search, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { search, type HitKind } from '../lib/search'
import { Rich, Tag } from './ui'

const KIND_CLS: Record<HitKind, string> = {
  Référence: 'text-cyan',
  MITRE: 'text-amber',
  Module: 'text-emerald',
  Playbook: 'text-violet-300',
  Alerte: 'text-red-300',
}

const SUGGESTIONS = ['4624', '4769', '1102', 'Sysmon 10', '445', 'certutil', 'DCSync']

export function CommandPalette({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [query, setQuery] = useState('')
  const [cursor, setCursor] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLUListElement>(null)
  const previousFocus = useRef<HTMLElement | null>(null)
  const navigate = useNavigate()
  const results = useMemo(() => search(query), [query])
  const current = results[cursor]

  useEffect(() => {
    if (open) {
      previousFocus.current = document.activeElement as HTMLElement | null
      setQuery('')
      setCursor(0)
      inputRef.current?.focus()
    } else {
      previousFocus.current?.focus()
    }
  }, [open])

  useEffect(() => {
    listRef.current?.querySelector('[aria-selected="true"]')?.scrollIntoView({ block: 'nearest' })
  }, [cursor])

  if (!open) return null

  const go = (to: string) => {
    onClose()
    navigate(to)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center bg-black/70 p-4 pt-[8vh]" onMouseDown={onClose}>
      <div
        role="dialog"
        aria-modal="true"
        aria-label="Recherche globale"
        onMouseDown={(e) => e.stopPropagation()}
        onKeyDown={(e) => {
          if (e.key === 'Escape') onClose()
          if (e.key !== 'Tab') return
          // Fenêtre modale : le clavier ne doit pas repartir dans la page derrière.
          const items = e.currentTarget.querySelectorAll<HTMLElement>('input, button')
          const edge = e.shiftKey ? items[0] : items[items.length - 1]
          if (document.activeElement === edge) {
            e.preventDefault()
            ;(e.shiftKey ? items[items.length - 1] : items[0]).focus()
          }
        }}
        className="flex max-h-[80vh] w-full max-w-3xl flex-col overflow-hidden rounded-lg border border-line bg-card shadow-2xl"
      >
        <div className="flex items-center gap-3 border-b border-line px-4">
          <Search size={18} className="shrink-0 text-cyan" aria-hidden />
          <input
            ref={inputRef}
            value={query}
            onChange={(e) => {
              setQuery(e.target.value)
              setCursor(0)
            }}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown') {
                e.preventDefault()
                setCursor((c) => Math.min(c + 1, results.length - 1))
              } else if (e.key === 'ArrowUp') {
                e.preventDefault()
                setCursor((c) => Math.max(c - 1, 0))
              } else if (e.key === 'Enter' && current) go(current.to)
            }}
            placeholder="Event ID, Sysmon, port, LOLBin, technique…"
            aria-label="Rechercher"
            className="w-full bg-transparent py-3.5 font-mono text-sm text-white placeholder:text-slate-500 focus:outline-none"
          />
          <button type="button" onClick={onClose} aria-label="Fermer" className="text-mute hover:text-white">
            <X size={18} />
          </button>
        </div>

        <div className="grid grid-cols-1 min-h-0 flex-1 md:grid-cols-[minmax(0,1fr)_minmax(0,1.1fr)]">
          <ul ref={listRef} role="listbox" aria-label="Résultats" className="min-h-0 overflow-y-auto p-2">
            {results.map((hit, i) => (
              <li key={hit.key} role="option" aria-selected={i === cursor}>
                <button
                  type="button"
                  onMouseEnter={() => setCursor(i)}
                  onClick={() => go(hit.to)}
                  className={`w-full rounded-md px-3 py-2 text-left ${i === cursor ? 'bg-raised' : ''}`}
                >
                  <span className="flex items-baseline gap-2">
                    <span className="font-mono text-sm font-bold text-white">{hit.label}</span>
                    <span className={`text-[11px] ${KIND_CLS[hit.kind]}`}>{hit.kind}</span>
                  </span>
                  <span className="block truncate text-xs text-mute">{hit.title}</span>
                </button>
              </li>
            ))}
            {query.trim() && !results.length && <li className="p-4 text-sm text-mute">Aucun résultat pour « {query} ».</li>}
            {!query.trim() && (
              <li className="p-3 text-sm text-mute">
                <p className="mb-2">Essayez :</p>
                <div className="flex flex-wrap gap-1.5">
                  {SUGGESTIONS.map((s) => (
                    <button key={s} type="button" onClick={() => setQuery(s)} className="rounded border border-line px-2 py-0.5 font-mono text-xs hover:border-cyan hover:text-white">
                      {s}
                    </button>
                  ))}
                </div>
              </li>
            )}
          </ul>

          {current && (
            <div className="hidden min-h-0 overflow-y-auto border-l border-line p-4 text-sm md:block">
              <Tag>{current.kind}</Tag>
              <h2 className="mt-2 font-mono text-lg font-bold text-white">{current.label}</h2>
              <p className="text-mute">{current.title}</p>
              {current.meaning && (
                <>
                  <h3 className="mt-4 text-xs font-semibold tracking-wide text-cyan uppercase">Signification</h3>
                  <p className="mt-1">
                    <Rich text={current.meaning} />
                  </p>
                </>
              )}
              {current.malicious && (
                <>
                  <h3 className="mt-4 text-xs font-semibold tracking-wide text-red-300 uppercase">Quand est-ce malveillant ?</h3>
                  <p className="mt-1">
                    <Rich text={current.malicious} />
                  </p>
                </>
              )}
              <p className="mt-4 flex items-center gap-1 text-xs text-mute">
                <CornerDownLeft size={12} aria-hidden /> Entrée pour ouvrir
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
