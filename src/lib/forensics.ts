/** Outils d'analyse du CyberLab. Tout s'exécute localement : aucune donnée ne quitte le navigateur. */
import { TLDS } from './tlds'

export function encodeUtf16Base64(text: string): string {
  let bin = ''
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i)
    bin += String.fromCharCode(c & 0xff, c >> 8)
  }
  return btoa(bin)
}

function base64ToBytes(input: string): Uint8Array {
  let s = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/')
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || !s.length) throw new Error('Entrée Base64 invalide')
  s = s.replace(/=+$/, '')
  if (s.length % 4 === 1) throw new Error('Entrée Base64 invalide (longueur incorrecte)')
  s += '='.repeat((4 - (s.length % 4)) % 4)
  return Uint8Array.from(atob(s), (c) => c.charCodeAt(0))
}

/** Isole la valeur de -enc / -e / -ec / -EncodedCommand si on colle une ligne de commande, même avec des ^ de cmd.exe. */
export function extractEncodedArg(input: string): string {
  const m = /(?:^|\s)[-/](?:e|ec|en|enc|enco|encod|encode|encoded|encodedc\w*)[\s:]+["']?([A-Za-z0-9+/=_-]{8,})["']?/i.exec(input.replace(/\^/g, ''))
  return m ? m[1] : input.trim()
}

export interface DecodeResult {
  encoding: 'UTF-16LE' | 'UTF-8'
  text: string
  extractedFromCommandLine: boolean
}

export function decodeBase64Auto(input: string): DecodeResult {
  const arg = extractEncodedArg(input)
  const bytes = base64ToBytes(arg)
  // PowerShell -EncodedCommand : UTF-16LE, donc un octet nul un caractère sur deux pour de l'ASCII.
  let nulls = 0
  for (let i = 1; i < bytes.length; i += 2) if (bytes[i] === 0) nulls++
  const utf16 = bytes.length >= 2 && bytes.length % 2 === 0 && nulls / (bytes.length / 2) > 0.6
  return {
    encoding: utf16 ? 'UTF-16LE' : 'UTF-8',
    text: new TextDecoder(utf16 ? 'utf-16le' : 'utf-8').decode(bytes),
    extractedFromCommandLine: arg !== input.trim(),
  }
}

export function hexDecode(input: string): string {
  const clean = input.replace(/0x|\\x|[\s:,-]/gi, '')
  if (!/^[0-9a-f]*$/i.test(clean) || !clean.length || clean.length % 2) throw new Error('Entrée hexadécimale invalide')
  const bytes = Uint8Array.from(clean.match(/.{2}/g) ?? [], (b) => parseInt(b, 16))
  return new TextDecoder().decode(bytes)
}

export function urlDecode(input: string): string {
  let current = input
  for (let i = 0; i < 3; i++) {
    // Séquence par séquence : un « 100% » isolé dans une URL réelle ne doit pas bloquer le reste du décodage.
    const next = current.replace(/\+/g, ' ').replace(/(?:%[0-9a-f]{2})+/gi, (run) => {
      try {
        return decodeURIComponent(run)
      } catch {
        return run
      }
    })
    if (next === current) break
    current = next
  }
  return current
}

const INDICATORS: [RegExp, string][] = [
  [/\b(?:IEX|Invoke-Expression)\b/i, 'Exécution de code en mémoire (IEX)'],
  [/DownloadString|DownloadFile|DownloadData|Invoke-WebRequest|\biwr\b|Start-BitsTransfer/i, 'Téléchargement distant'],
  [/FromBase64String/i, 'Seconde couche Base64'],
  [/GzipStream|DeflateStream/i, 'Charge compressée'],
  [/-w(?:indowstyle)?\s+hidden|-nop\b|-noni\b|bypass/i, 'Options de furtivité'],
  [/VirtualAlloc|WriteProcessMemory|CreateRemoteThread/i, 'API d’injection mémoire'],
  [/AmsiUtils|amsiInitFailed/i, 'Contournement AMSI'],
  [/Add-MpPreference|Set-MpPreference/i, 'Altération de Defender'],
  [/vssadmin|wbadmin|bcdedit/i, 'Destruction des sauvegardes'],
  [/mimikatz|sekurlsa|lsass/i, 'Vol d’identifiants'],
]

export function findIndicators(text: string): string[] {
  return INDICATORS.filter(([re]) => re.test(text)).map(([, label]) => label)
}

export function defang(input: string): string {
  const SCHEMES: Record<string, string> = { http: 'hxxp', https: 'hxxps', ftp: 'fxp' }
  return input
    .replace(/\b(https?|ftp):\/\/([^\s/?#"'<>]+)/gi, (_m, scheme: string, host: string) => `${SCHEMES[scheme.toLowerCase()]}[://]${host.replace(/\./g, '[.]')}`)
    .replace(/(?<!\[)@(?!\])/g, '[@]')
    .replace(/\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b/g, '$1[.]$2[.]$3[.]$4')
    .replace(/(?<![\w/.-])(?:[a-z0-9-]+\.)+[a-z]{2,}\b/gi, (host) => (isRealTld(host.split('.').at(-1)!) ? host.replace(/\./g, '[.]') : host))
}

export function refang(input: string): string {
  return input
    .replace(/h(?:xx|XX)p(s?)(?:\[:\/\/\]|\[:\]\/\/|:\/\/)/g, 'http$1://')
    .replace(/fxp(?:\[:\/\/\]|:\/\/)/gi, 'ftp://')
    .replace(/\[\.\]|\(\.\)|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[@\]|\[at\]|\(at\)/gi, '@')
    .replace(/\[:\]/g, ':')
    .replace(/\[\/\]/g, '/')
}

export interface Iocs {
  ipv4: string[]
  urls: string[]
  domains: string[]
  emails: string[]
  md5: string[]
  sha1: string[]
  sha256: string[]
  cves: string[]
}

// Certaines extensions sont aussi de vrais TLD (.zip, .bat…) : on les exclut pour ne pas remonter invoice.zip.
const FILE_EXTENSIONS = new Set(
  'exe dll sys bat cmd ps1 psm1 vbs vbe js jse hta lnk iso img msi scr pif zip rar gz 7z tar doc docx docm xls xlsx xlsm ppt pptx pdf txt log csv json xml yml yaml html htm php asp aspx jsp png jpg jpeg gif svg tmp dat bin ini cfg conf db evtx pcap'.split(' '),
)

// TLD de marques qui sont aussi des noms de famille : adm.dupont est un compte dans les logs, pas un domaine.
const SURNAME_TLDS = new Set(['dupont', 'ford', 'lincoln', 'chase'])

function isRealTld(label: string) {
  const tld = label.toLowerCase()
  return TLDS.has(tld) && !FILE_EXTENSIONS.has(tld) && !SURNAME_TLDS.has(tld)
}

const uniq = (items: string[]) => [...new Set(items)]

export function isPrivateIp(ip: string): boolean {
  const [a, b] = ip.split('.').map(Number)
  return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || a >= 224
}

export function extractIocs(raw: string): Iocs {
  const text = refang(raw)
  const hashes = (len: number) => uniq(text.match(new RegExp(`\\b[a-fA-F0-9]{${len}}\\b`, 'g')) ?? []).map((h) => h.toLowerCase())
  const urls = uniq((text.match(/\b(?:https?|ftp):\/\/[^\s"'<>)\]]+/gi) ?? []).map((u) => u.replace(/[.,;]+$/, '')))
  const emails = uniq((text.match(/\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+\b/gi) ?? []).map((e) => e.toLowerCase()))
  const ipv4 = uniq(text.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) ?? [])
  const domains = uniq(
    (text.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,23}\b/gi) ?? [])
      .map((d) => d.toLowerCase())
      .filter((d) => isRealTld(d.split('.').at(-1) ?? '')),
  )
  return {
    ipv4,
    urls,
    domains,
    emails,
    md5: hashes(32),
    sha1: hashes(40),
    sha256: hashes(64),
    cves: uniq((text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) ?? []).map((c) => c.toUpperCase())),
  }
}

export interface HeaderField {
  name: string
  value: string
}

export interface HopInfo {
  index: number
  raw: string
  from: string
  by: string
  ip?: string
  date?: string
}

export interface HeaderReport {
  fields: HeaderField[]
  hops: HopInfo[]
  originIp?: string
  spf?: string
  dkim?: string
  dmarc?: string
  from?: string
  returnPath?: string
  replyTo?: string
  subject?: string
  findings: { level: 'danger' | 'warn' | 'ok'; text: string }[]
}

function domainOf(addr?: string) {
  const m = addr ? /@([a-z0-9.-]+)/i.exec(addr) : null
  return m?.[1].toLowerCase()
}

/** Compare les deux derniers labels : suffisant ici, sans liste complète des suffixes publics. */
function orgDomain(d?: string) {
  return d?.split('.').slice(-2).join('.')
}

export function analyzeHeaders(raw: string): HeaderReport {
  const fields: HeaderField[] = []
  // La première ligne vide termine les en-têtes : un « Reply-To: » écrit dans le corps ne compte pas.
  const headerPart = raw.replace(/\r\n/g, '\n').trimStart().split(/\n[ \t]*\n/)[0]
  for (const line of headerPart.split('\n')) {
    if (/^[ \t]/.test(line) && fields.length) {
      fields[fields.length - 1].value += ' ' + line.trim()
    } else {
      const m = /^([A-Za-z][\w-]*):\s*(.*)$/.exec(line)
      if (m) fields.push({ name: m[1], value: m[2] })
    }
  }
  const get = (n: string) => fields.find((f) => f.name.toLowerCase() === n)?.value
  const received = fields.filter((f) => f.name.toLowerCase() === 'received')
  // Chaque relais ajoute son Received au-dessus : le dernier de la liste est le plus proche de l'expéditeur.
  const hops: HopInfo[] = [...received].reverse().map((f, i) => ({
    index: i + 1,
    raw: f.value,
    from: /from\s+(\S+)/i.exec(f.value)?.[1] ?? '?',
    by: /by\s+(\S+)/i.exec(f.value)?.[1] ?? '?',
    // Seulement avant « by » : l'IP qui suit est celle du serveur qui reçoit, pas celle de l'expéditeur.
    ip: /[[(](\d{1,3}(?:\.\d{1,3}){3}|[0-9a-f]{1,4}(?::[0-9a-f]{0,4}){3,})[\])]/i.exec(f.value.split(/\bby\s/i)[0])?.[1],
    date: f.value.split(';').at(-1)?.trim(),
  }))
  const auth = fields.filter((f) => f.name.toLowerCase() === 'authentication-results').map((f) => f.value).join(' ')
  const verdict = (k: string) => new RegExp(`\\b${k}=(\\w+)`, 'i').exec(auth)?.[1]?.toLowerCase()
  const receivedSpf = get('received-spf')
  const spf = verdict('spf') ?? /^\s*(\w+)/.exec(receivedSpf ?? '')?.[1]?.toLowerCase()
  const dkim = verdict('dkim')
  const dmarc = verdict('dmarc')
  const from = get('from')
  const returnPath = get('return-path')
  const replyTo = get('reply-to')
  const findings: HeaderReport['findings'] = []

  const originIp = hops.find((h) => h.ip && !isPrivateIp(h.ip))?.ip ?? hops[0]?.ip
  if (spf && spf !== 'pass') findings.push({ level: spf === 'fail' ? 'danger' : 'warn', text: `SPF = ${spf} : l'IP source n'est pas pleinement autorisée par le domaine de l'enveloppe.` })
  if (dkim && dkim !== 'pass') findings.push({ level: dkim === 'none' ? 'warn' : 'danger', text: `DKIM = ${dkim} : signature absente ou invalide, le message n'est pas authentifié cryptographiquement.` })
  if (dmarc === 'none') findings.push({ level: 'warn', text: 'DMARC = none : le domaine ne publie aucune politique DMARC, le From visible n’est donc pas protégé.' })
  else if (dmarc && dmarc !== 'pass') findings.push({ level: 'danger', text: `DMARC = ${dmarc} : ni SPF ni DKIM ne sont alignés avec le domaine du From visible.` })
  if (spf === 'pass' && dmarc && dmarc !== 'pass') findings.push({ level: 'warn', text: 'SPF passe mais DMARC échoue : SPF valide le domaine de l’enveloppe, pas celui affiché à l’utilisateur.' })

  const fromD = domainOf(from)
  const rpD = domainOf(returnPath)
  const rtD = domainOf(replyTo)
  if (fromD && rpD && orgDomain(fromD) !== orgDomain(rpD)) findings.push({ level: 'warn', text: `Return-Path (${rpD}) différent du From (${fromD}) : à confirmer, les routeurs légitimes font pareil.` })
  if (fromD && rtD && orgDomain(fromD) !== orgDomain(rtD)) findings.push({ level: 'danger', text: `Reply-To (${rtD}) différent du From (${fromD}) : les réponses partent vers un autre domaine.` })
  if (!auth) findings.push({ level: 'warn', text: receivedSpf ? 'Pas d’Authentication-Results : seul SPF est connu, via Received-SPF. Impossible de conclure sur DKIM et DMARC.' : 'Aucun en-tête Authentication-Results : impossible de conclure sur SPF, DKIM et DMARC.' })
  if (!findings.some((f) => f.level !== 'ok') && auth) findings.push({ level: 'ok', text: 'Authentification alignée. Ce n’est pas une preuve de légitimité : un compte réellement compromis passe aussi.' })

  return { fields, hops, originIp, spf, dkim, dmarc, from, returnPath, replyTo, subject: get('subject'), findings }
}
