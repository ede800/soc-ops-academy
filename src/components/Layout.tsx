import {
  BookOpen,
  ClipboardList,
  FileText,
  FlaskConical,
  Gauge,
  Library,
  Menu,
  Search,
  Siren,
  Target,
  Trophy,
  X,
} from 'lucide-react'
import { useEffect, useState, type ReactNode } from 'react'
import { NavLink, useLocation } from 'react-router-dom'
import { computeXp, rankFor, useProgress } from '../lib/progress'
import { totals } from '../lib/totals'
import { CommandPalette } from './CommandPalette'
import { ProgressBar } from './ui'

const NAV = [
  { to: '/', label: 'Tableau de bord', icon: Gauge, end: true },
  { to: '/modules', label: 'Modules de cours', icon: BookOpen },
  { to: '/soc-queue', label: 'Live SOC Queue', icon: Siren },
  { to: '/cyberlab', label: 'SOC CyberLab', icon: FlaskConical },
  { to: '/mitre', label: 'MITRE ATT&CK', icon: Target },
  { to: '/playbooks', label: 'Playbooks', icon: ClipboardList },
  { to: '/cheat-sheets', label: 'Cheat sheets', icon: Library },
  { to: '/rapport', label: 'Rapport d’incident', icon: FileText },
]

function SidebarContent({ onSearch }: { onSearch: () => void }) {
  const { progress } = useProgress()
  const xp = computeXp(progress, totals)
  const { rank, next, ratio } = rankFor(xp)
  return (
    <>
      <div className="flex items-center gap-2.5 px-4 pt-5 pb-4">
        <img src="./favicon.svg" alt="" width={30} height={30} />
        <div className="leading-tight">
          <p className="font-bold text-white">SOC Ops Academy</p>
          <p className="font-mono text-[10px] tracking-widest text-cyan uppercase">Command Center</p>
        </div>
      </div>

      <div className="mx-3 rounded-md border border-line bg-bg p-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-white">
          <Trophy size={15} className="text-amber" aria-hidden /> {rank.name}
        </div>
        <div className="my-2">
          <ProgressBar value={ratio} tone="bg-emerald" label="Progression vers le rang suivant" />
        </div>
        <p className="font-mono text-xs text-mute">
          {xp} XP{next ? ` · ${next.min - xp} avant ${next.name}` : ' · rang maximal'}
        </p>
      </div>

      <button
        type="button"
        onClick={onSearch}
        className="mx-3 mt-3 flex items-center gap-2 rounded-md border border-line px-3 py-2 text-sm text-mute transition hover:border-cyan hover:text-white"
      >
        <Search size={15} aria-hidden />
        <span className="flex-1 text-left">Rechercher</span>
        <kbd className="rounded border border-line px-1.5 font-mono text-[10px]">Ctrl K</kbd>
      </button>

      <nav aria-label="Navigation principale" className="mt-3 flex-1 space-y-0.5 overflow-y-auto px-3 pb-4">
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              `flex items-center gap-2.5 rounded-md border-l-2 px-3 py-2 text-sm transition ${
                isActive ? 'border-cyan bg-raised font-medium text-white' : 'border-transparent text-mute hover:bg-raised/60 hover:text-white'
              }`
            }
          >
            <item.icon size={16} aria-hidden /> {item.label}
          </NavLink>
        ))}
      </nav>
    </>
  )
}

export function Layout({ children }: { children: ReactNode }) {
  const [menuOpen, setMenuOpen] = useState(false)
  const [searchOpen, setSearchOpen] = useState(false)
  const { pathname } = useLocation()

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault()
        setSearchOpen((o) => !o)
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  useEffect(() => {
    setMenuOpen(false)
    window.scrollTo(0, 0)
  }, [pathname])

  const openSearch = () => {
    setMenuOpen(false)
    setSearchOpen(true)
  }

  return (
    <div className="min-h-dvh">
      <aside className="fixed inset-y-0 left-0 hidden w-64 flex-col border-r border-line bg-card lg:flex">
        <SidebarContent onSearch={openSearch} />
      </aside>

      <header className="sticky top-0 z-30 flex items-center justify-between border-b border-line bg-card px-4 py-2.5 lg:hidden">
        <button type="button" aria-label="Ouvrir le menu" onClick={() => setMenuOpen(true)} className="text-ink">
          <Menu size={22} />
        </button>
        <span className="font-bold text-white">SOC Ops Academy</span>
        <button type="button" aria-label="Rechercher" onClick={openSearch} className="text-ink">
          <Search size={20} />
        </button>
      </header>

      {menuOpen && (
        <div className="fixed inset-0 z-40 lg:hidden">
          <div className="absolute inset-0 bg-black/60" onClick={() => setMenuOpen(false)} />
          <aside className="absolute inset-y-0 left-0 flex w-72 max-w-[85vw] flex-col border-r border-line bg-card">
            <button type="button" aria-label="Fermer le menu" onClick={() => setMenuOpen(false)} className="absolute top-5 right-3 text-mute">
              <X size={20} />
            </button>
            <SidebarContent onSearch={openSearch} />
          </aside>
        </div>
      )}

      <main className="lg:pl-64">
        <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6 lg:py-8">{children}</div>
      </main>

      <CommandPalette open={searchOpen} onClose={() => setSearchOpen(false)} />
    </div>
  )
}
