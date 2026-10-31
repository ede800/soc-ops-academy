import { ArrowRight, Check, Copy, Info, Lightbulb, OctagonAlert, TriangleAlert } from 'lucide-react'
import { Fragment, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { highlight } from '../lib/highlight'
import type { Block, Lang, Severity } from '../types'

/** Rend `code` et **gras** dans les textes de cours. Passe par React : aucun HTML injecté. */
export function Rich({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
  return (
    <>
      {parts.map((part, i) => {
        if (part.startsWith('`') && part.endsWith('`') && part.length > 1) {
          return (
            <code key={i} className="rounded border border-line bg-bg px-1 py-px font-mono text-[0.86em] break-words text-cyan-300">
              {part.slice(1, -1)}
            </code>
          )
        }
        if (part.startsWith('**') && part.endsWith('**') && part.length > 3) {
          return (
            <strong key={i} className="font-semibold text-white">
              {part.slice(2, -2)}
            </strong>
          )
        }
        return <Fragment key={i}>{part}</Fragment>
      })}
    </>
  )
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

export function CopyButton({ text, label = 'Copier' }: { text: string; label?: string }) {
  const [state, setState] = useState<'idle' | 'ok' | 'ko'>('idle')
  return (
    <button
      type="button"
      onClick={async () => {
        setState((await copyText(text)) ? 'ok' : 'ko')
        setTimeout(() => setState('idle'), 1600)
      }}
      className="inline-flex shrink-0 items-center gap-1.5 rounded border border-line px-2 py-1 font-sans text-xs text-mute transition hover:border-cyan hover:text-white"
    >
      {state === 'ok' ? <Check size={13} className="text-emerald" /> : <Copy size={13} />}
      {state === 'ok' ? 'Copié' : state === 'ko' ? 'Échec' : label}
    </button>
  )
}

export function CodeBlock({ code, lang, title }: { code: string; lang: Lang; title?: string }) {
  return (
    <figure className="my-4 overflow-hidden rounded-md border border-line bg-[#0b111d]">
      <figcaption className="flex items-center justify-between gap-3 border-b border-line px-3 py-1.5">
        <span className="min-w-0 truncate text-xs text-mute">
          {lang !== 'text' && <span className="mr-2 font-mono font-bold text-cyan uppercase">{lang}</span>}
          {title}
        </span>
        <CopyButton text={code} />
      </figcaption>
      <pre tabIndex={0} className="overflow-x-auto p-3 font-mono text-[12.5px] leading-relaxed text-slate-200">
        <code>{highlight(code, lang)}</code>
      </pre>
    </figure>
  )
}

const CALLOUTS = {
  info: { icon: Info, cls: 'border-cyan/50 bg-cyan/5', ic: 'text-cyan' },
  tip: { icon: Lightbulb, cls: 'border-emerald/50 bg-emerald/5', ic: 'text-emerald' },
  warn: { icon: TriangleAlert, cls: 'border-amber/50 bg-amber/5', ic: 'text-amber' },
  danger: { icon: OctagonAlert, cls: 'border-crimson/50 bg-crimson/5', ic: 'text-crimson' },
}

export function DataTable({ headers, rows }: { headers: string[]; rows: string[][] }) {
  return (
    <div className="my-4 overflow-x-auto rounded-md border border-line">
      <table className="w-full min-w-[32rem] border-collapse text-left text-sm">
        <thead className="bg-raised text-xs tracking-wide text-mute uppercase">
          <tr>
            {headers.map((head) => (
              <th key={head} scope="col" className="px-3 py-2 font-semibold">
                {head}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-t border-line align-top">
              {row.map((cell, j) => (
                <td key={j} className="px-3 py-2">
                  <Rich text={cell} />
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

export function BlockView({ block }: { block: Block }) {
  switch (block.type) {
    case 'p':
      return (
        <p className="my-3">
          <Rich text={block.text} />
        </p>
      )
    case 'h':
      return <h4 className="mt-6 mb-2 font-semibold text-white">{block.text}</h4>
    case 'list': {
      const Tag = block.ordered ? 'ol' : 'ul'
      return (
        <Tag className={`my-3 space-y-1.5 pl-5 ${block.ordered ? 'list-decimal' : 'list-disc'} marker:text-cyan`}>
          {block.items.map((item, i) => (
            <li key={i}>
              <Rich text={item} />
            </li>
          ))}
        </Tag>
      )
    }
    case 'table':
      return <DataTable headers={block.headers} rows={block.rows} />
    case 'code':
      return <CodeBlock code={block.code} lang={block.lang} title={block.title} />
    case 'links':
      return (
        <ul className="my-4 grid grid-cols-1 gap-2 sm:grid-cols-2">
          {block.items.map((item) => (
            <li key={item.to}>
              <Link to={item.to} className="flex h-full items-center justify-between gap-2 rounded-md border border-line bg-card p-3 text-sm font-medium text-white transition hover:border-cyan">
                {item.label} <ArrowRight size={14} className="shrink-0 text-cyan" aria-hidden />
              </Link>
            </li>
          ))}
        </ul>
      )
    case 'callout': {
      const c = CALLOUTS[block.tone]
      return (
        <aside className={`my-4 flex gap-3 rounded-md border-l-4 border-y border-r p-3 ${c.cls}`}>
          <c.icon size={18} className={`mt-0.5 shrink-0 ${c.ic}`} aria-hidden />
          <div>
            <p className="font-semibold text-white">
              <Rich text={block.title} />
            </p>
            <p className="mt-1 text-sm">
              <Rich text={block.text} />
            </p>
          </div>
        </aside>
      )
    }
  }
}

const SEVERITY: Record<Severity, string> = {
  Critique: 'border-crimson/60 bg-crimson/15 text-red-300',
  Haute: 'border-amber/60 bg-amber/15 text-amber-300',
  Moyenne: 'border-cyan/60 bg-cyan/15 text-cyan-300',
  Basse: 'border-emerald/60 bg-emerald/15 text-emerald-300',
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`inline-block rounded border px-1.5 py-0.5 text-xs font-semibold ${SEVERITY[severity]}`}>{severity}</span>
}

export function Tag({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <span className={`inline-block rounded border border-line bg-raised px-1.5 py-0.5 font-mono text-xs text-mute ${className}`}>{children}</span>
}

export function Card({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`rounded-lg border border-line bg-card ${className}`}>{children}</div>
}

export function PageHeader({ eyebrow, title, children }: { eyebrow?: string; title: string; children?: ReactNode }) {
  return (
    <header className="mb-6">
      {eyebrow && <p className="mb-1 font-mono text-xs tracking-widest text-cyan uppercase">{eyebrow}</p>}
      <h1 className="text-2xl font-bold text-white sm:text-3xl">{title}</h1>
      {children && <div className="mt-2 max-w-3xl text-mute">{children}</div>}
    </header>
  )
}

export function ProgressBar({ value, tone = 'bg-cyan', label }: { value: number; tone?: string; label: string }) {
  const pct = Math.round(Math.max(0, Math.min(1, value)) * 100)
  return (
    <div role="progressbar" aria-label={label} aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} className="h-1.5 overflow-hidden rounded-full bg-line">
      <div className={`h-full rounded-full ${tone} transition-all duration-500`} style={{ width: `${pct}%` }} />
    </div>
  )
}

export const inputCls =
  'w-full rounded-md border border-line bg-bg px-3 py-2 text-sm text-ink placeholder:text-slate-500 focus:border-cyan focus:outline-none'
export const btnPrimary =
  'inline-flex items-center justify-center gap-2 rounded-md bg-cyan px-4 py-2 text-sm font-semibold text-slate-950 transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-50'
export const btnGhost =
  'inline-flex items-center justify-center gap-2 rounded-md border border-line px-3 py-2 text-sm text-ink transition hover:border-cyan hover:text-white'
