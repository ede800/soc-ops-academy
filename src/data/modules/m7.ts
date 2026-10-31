import type { Module } from '../../types'
import { code, h, info, ol, p, r, table, tip, warn } from '../blocks'

export const m7: Module = {
  id: 'hunting',
  number: 7,
  title: 'Threat hunting, forensique et detection engineering',
  tier: 'N3',
  summary:
    "Passer de la réaction à l'initiative : mener une chasse à partir d'une hypothèse, exploiter les artefacts forensiques et produire des détections testées, maintenues et mesurées.",
  objectives: [
    'Formuler une hypothèse de chasse testable',
    'Utiliser stacking, baseline et analyse de la longue traîne',
    'Exploiter les artefacts Windows et l’analyse mémoire',
    'Gérer les détections comme du code, avec tests et métriques',
  ],
  sections: [
    {
      id: 'hunt',
      title: 'Threat hunting par hypothèse',
      blocks: [
        p("Le hunting part d'un postulat : un attaquant est peut-être déjà présent, et aucune alerte ne l'a signalé. Sans hypothèse, on ne fait que parcourir des logs. Le résultat utile d'une chasse n'est pas seulement une compromission découverte : c'est aussi une détection nouvelle ou un angle mort identifié."),
        table(
          ['Source d’hypothèse', 'Exemple'],
          ['Threat intelligence', '« Ce groupe vise notre secteur et utilise `rclone` pour exfiltrer : est-il présent chez nous ? »'],
          ['ATT&CK et couverture', '« Nous n’avons aucune détection sur `T1021.006` (WinRM) : y a-t-il de l’activité inhabituelle ? »'],
          ['Connaissance interne', '« Les comptes de service ne devraient jamais ouvrir de session interactive. Est-ce vrai ? »'],
          ['Suite d’incident', '« L’attaquant a utilisé cette DLL ici : est-elle présente ailleurs ? »'],
        ),
        h('Le cycle (inspiré de PEAK et TaHiTI)'),
        ol(
          '**Préparer** : hypothèse, ATT&CK, données nécessaires, durée.',
          '**Vérifier les données** : la télémétrie existe-t-elle vraiment sur la période ?',
          '**Chercher** : commencer large, puis affiner.',
          '**Analyser** : expliquer chaque anomalie, ou l’écarter avec une preuve.',
          '**Conclure** : incident, nouvelle règle, ou angle mort documenté.',
          '**Capitaliser** : conserver les requêtes et le raisonnement pour rejouer la chasse.',
        ),
        h('Techniques d’analyse'),
        table(
          ['Technique', 'Principe', 'Exemple'],
          ['Stacking', 'Compter et lire la queue de distribution', 'Parents de `powershell.exe` triés par rareté'],
          ['Baseline', 'Comparer à la normale', 'Comptes se connectant à plus de N machines cette semaine par rapport à 30 jours'],
          ['Regroupement temporel', 'Chercher les événements en rafale', '`whoami`, `net group`, `nltest` en moins de 5 minutes'],
          ['Pivot', 'Partir d’un indice pour élargir', 'Du hash vers les hôtes, puis vers les comptes et le réseau'],
        ),
        code('kql', 'Chasse : rafale de commandes de découverte', r`
let Recon = dynamic(["whoami.exe","net.exe","net1.exe","nltest.exe","systeminfo.exe","ipconfig.exe","tasklist.exe","quser.exe","arp.exe"]);
DeviceProcessEvents
| where Timestamp > ago(14d) and FileName in~ (Recon)
| summarize Outils = dcount(FileName), Liste = make_set(FileName, 20), Parents = make_set(InitiatingProcessFileName, 10)
    by DeviceName, AccountName, bin(Timestamp, 5m)
| where Outils >= 4
| order by Outils desc
`),
        code('spl', 'Chasse : parents rares de PowerShell', r`
index=sysmon EventCode=1 Image="*\\powershell.exe" earliest=-30d
| stats count dc(host) as hotes values(host) as liste by ParentImage
| sort + count
| head 30
`),
        code('kql', 'Chasse : comptes de service en session interactive', r`
SecurityEvent
| where EventID == 4624 and LogonType in (2, 10)
| where TargetUserName startswith "svc"
| summarize Sessions = count(), Hotes = make_set(Computer, 20), Sources = make_set(IpAddress, 20) by TargetUserName
`),
        tip('Une chasse sans résultat reste utile', "« Aucune trace sur 90 jours, télémétrie vérifiée sur 98 % du parc, voici la requête » est une conclusion valable : elle réduit l'incertitude et elle peut devenir une détection planifiée."),
      ],
    },
    {
      id: 'forensics',
      title: 'Forensique Windows et mémoire',
      blocks: [
        table(
          ['Artefact', 'Emplacement', 'Ce qu’il prouve', 'Outil', 'Limite'],
          ['Prefetch', '`C:\\Windows\\Prefetch\\*.pf`', 'Exécution, dates, fichiers chargés', '`PECmd`', 'Désactivé par défaut sur certains serveurs'],
          ['Amcache', '`C:\\Windows\\AppCompat\\Programs\\Amcache.hve`', 'Présence, SHA-1', '`AmcacheParser`', 'Pas une preuve d’exécution à elle seule'],
          ['ShimCache', 'Clé `AppCompatCache` du registre', 'Présence d’un binaire', '`AppCompatCacheParser`', 'Sur Windows 10+, ne prouve pas l’exécution'],
          ['MFT', '`$MFT`', 'Dates de tous les fichiers', '`MFTECmd`', 'Timestomping : comparez `$SI` et `$FN`'],
          ['UsnJrnl', '`$Extend\\$UsnJrnl:$J`', 'Créations, suppressions, renommages', '`MFTECmd`', 'Historique limité'],
          ['ShellBags', 'Registre utilisateur', 'Dossiers parcourus', '`SBECmd`', 'Interactif seulement'],
          ['LNK, Jump Lists', 'Profil utilisateur', 'Fichiers ouverts, y compris sur partages', '`LECmd`, `JLECmd`', 'Propre à chaque utilisateur'],
          ['SRUM', '`C:\\Windows\\System32\\sru\\SRUDB.dat`', 'Octets envoyés par application, environ 30 jours', '`SrumECmd`', 'Excellent pour l’exfiltration'],
          ['Tâches, services', 'Registre, `C:\\Windows\\System32\\Tasks`', 'Persistance', '`Autoruns`', '—'],
        ),
        code('powershell', 'EZ Tools et collecte', r`
# Triage à chaud avec KAPE
kape.exe --tsource C: --tdest D:\triage --target !SANS_Triage --vhdx %m

# Prefetch et MFT au format CSV
PECmd.exe -d D:\triage\C\Windows\Prefetch --csv D:\out
MFTECmd.exe -f 'D:\triage\C\$MFT' --csv D:\out

# Journaux EVTX
EvtxECmd.exe -d D:\triage\C\Windows\System32\winevt\Logs --csv D:\out

# Chasse rapide dans les EVTX avec des règles Sigma
hayabusa.exe csv-timeline -d D:\triage\C\Windows\System32\winevt\Logs -o D:\out\timeline.csv
`),
        h('Analyse mémoire avec Volatility 3'),
        code('bash', 'Les plugins essentiels', r`
vol -f mem.raw windows.info                # Profil du système
vol -f mem.raw windows.pstree              # Arbre des processus
vol -f mem.raw windows.cmdline             # Lignes de commande
vol -f mem.raw windows.netscan             # Connexions, y compris fermées
vol -f mem.raw windows.malfind             # Régions RWX, code injecté
vol -f mem.raw windows.dlllist --pid 4242  # DLL d'un processus
vol -f mem.raw windows.svcscan             # Services
vol -f mem.raw windows.psscan              # Processus cachés de la liste standard
`),
        table(
          ['Processus', 'Parent attendu', 'Anomalie'],
          ['`svchost.exe`', '`services.exe`', 'Autre parent, chemin hors de `System32`'],
          ['`lsass.exe`', '`wininit.exe`', 'Plus d’une instance'],
          ['`services.exe`', '`wininit.exe`', 'Plus d’une instance'],
          ['`explorer.exe`', '`userinit.exe` (qui se termine ensuite)', 'Chemin différent de `C:\\Windows`'],
        ),
        warn('Présence n’est pas exécution', "Un binaire présent dans ShimCache ou Amcache a pu seulement être vu par Windows. Pour affirmer une exécution, recoupez avec Prefetch, le `4688`, Sysmon `1` ou l'EDR. Cette nuance évite de fausses conclusions dans un rapport."),
      ],
    },
    {
      id: 'detection',
      title: 'Detection engineering',
      blocks: [
        p("Une détection est un produit logiciel : elle a un besoin, des tests, une mise en production, une maintenance et une fin de vie."),
        h('Cycle de vie'),
        ol(
          '**Besoin** : menace ciblée, technique ATT&CK, source de données disponible.',
          "**Recherche** : comment la technique fonctionne, ce qu'elle laisse comme trace, avec une reproduction en laboratoire.",
          '**Écriture** : règle Sigma ou native, en ciblant le comportement plutôt que l’outil.',
          "**Test** : exécuter l'attaque (Atomic Red Team), puis mesurer le bruit sur 30 jours d'historique.",
          '**Déploiement** : passage progressif, d’abord en silencieux, avec instructions de triage.',
          '**Maintenance** : revoir les faux positifs et réévaluer la valeur de la règle.',
        ),
        code('powershell', 'Tester avec Atomic Red Team (sur machine de lab uniquement)', r`
Install-Module -Name invoke-atomicredteam -Scope CurrentUser
Invoke-AtomicTest T1059.001 -ShowDetailsBrief
Invoke-AtomicTest T1059.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 1
Invoke-AtomicTest T1059.001 -TestNumbers 1 -Cleanup
`),
        warn('Sur un parc isolé uniquement', "Ces tests exécutent de vraies techniques offensives. Utilisez une machine de laboratoire ou obtenez une autorisation écrite, en prévenant le SOC si le test a lieu en production."),
        h('Viser le comportement plutôt que le nom'),
        table(
          ['Niveau', 'Exemple', 'Robustesse'],
          ['Faible', '`Image` se termine par `mimikatz.exe`', 'Il suffit de renommer le fichier'],
          ['Moyen', '`CommandLine` contient `sekurlsa::`', 'Résiste au renommage, pas à l’obfuscation'],
          ['Élevé', 'Lecture de la mémoire de `lsass.exe` par un binaire non signé hors liste', 'Force à changer de technique'],
        ),
        h('Détection as code'),
        code('text', 'Organisation type d’un dépôt', r`
detections/
  credential_access/
    lsass_access.yml        # Règle Sigma
    lsass_access.test.json  # Événements attendus
  runbooks/
    lsass_access.md         # Instructions de triage N1
.github/workflows/
  validate.yml              # Lint Sigma, conversion, tests
  deploy.yml                # Publication via l'API du SIEM
`),
        h('Mesurer sa valeur'),
        table(
          ['Métrique', 'Question', 'Action si mauvaise'],
          ['Précision (TP / total)', 'Combien de déclenchements sont réels ?', 'Affiner ou retirer'],
          ['Volume par semaine', 'Est-ce traitable ?', 'Agréger ou baisser la sévérité'],
          ['Temps de triage', 'Le N1 sait-il quoi faire ?', 'Améliorer le runbook'],
          ['Tests réussis', 'La règle fonctionne-t-elle encore ?', 'Corriger'],
          ['Couverture ATT&CK', 'Quels angles morts ?', 'Prioriser selon la menace, sans viser 100 %'],
        ),
        info('La couverture ATT&CK peut induire en erreur', "Une technique « couverte » par une seule règle fragile reste un angle mort. Utilisez ATT&CK Navigator pour guider vos priorités, en notant le niveau de confiance et pas seulement une case verte."),
        tip('Un bon runbook vaut une bonne règle', "Chaque règle devrait préciser : ce qu'elle cherche, comment la vérifier, les faux positifs courants et la suite à donner. C'est ce qui réduit réellement le temps de triage du N1."),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['Besoin', 'Artefact ou outil'],
      ['Preuve d’exécution', 'Prefetch, Sysmon `1`, `4688`, EDR'],
      ['Présence d’un fichier', 'Amcache, ShimCache, MFT'],
      ['Volume exfiltré par application', 'SRUM'],
      ['Timestomping', 'Comparez `$STANDARD_INFORMATION` et `$FILE_NAME`'],
      ['Timeline EVTX rapide', 'Hayabusa, Chainsaw'],
      ['Injection', '`windows.malfind`, Sysmon `8`'],
      ['Connexions passées', '`windows.netscan`'],
      ['Tester une règle', 'Atomic Red Team, en laboratoire'],
    ),
    code('text', 'Canevas d’une chasse', r`
Hypothèse : ......................................................
ATT&CK    : T....      Données : ............ Période : .........
Requêtes  : (liens vers le dépôt)
Résultats : ..... hôtes analysés, ..... anomalies expliquées
Conclusion: [ ] Incident  [ ] Nouvelle règle  [ ] Angle mort  [ ] R.A.S.
`),
  ],
  quiz: [
    {
      q: 'Laquelle de ces formulations est une véritable hypothèse de chasse ?',
      options: [
        '« Regarder les logs PowerShell »',
        '« Des attaquants pourraient utiliser `rclone` pour exfiltrer vers un cloud : chercher `rclone` et ses arguments dans Sysmon 1 sur 90 jours »',
        '« Trouver des menaces »',
        '« Lire le dernier rapport CTI, résumer les groupes qui visent notre secteur, puis partager ce résumé avec l’équipe à la prochaine réunion hebdomadaire »',
      ],
      answer: 1,
      explain: 'Une hypothèse est testable : elle indique le comportement recherché, la donnée et la période.',
    },
    {
      q: 'Quel artefact prouve le mieux l’exécution d’un binaire ?',
      options: ['ShimCache sur Windows 10', 'Prefetch', 'Le simple fichier dans `Temp`', 'Une entrée Amcache seule'],
      answer: 1,
      explain: 'Prefetch est créé à l’exécution. ShimCache et Amcache peuvent refléter une simple présence.',
    },
    {
      q: 'Quel plugin Volatility 3 repère le mieux du code injecté ?',
      options: ['`windows.info`', '`windows.malfind`', '`windows.cmdline`', '`windows.svcscan`'],
      answer: 1,
      explain: '`malfind` cherche les régions mémoire exécutables et écrites sans correspondance avec un fichier sur disque.',
    },
    {
      q: 'Que montre cet arbre ?',
      evidence: { lang: 'text', code: 'explorer.exe (1820)\n└─ svchost.exe (4242)  C:\\Users\\Public\\svchost.exe' },
      options: ['Un fonctionnement normal', 'Un faux svchost : mauvais parent, mauvais chemin', 'Un service Windows Update', 'Une mise à jour de l’antivirus'],
      answer: 1,
      explain: 'Le vrai `svchost.exe` se trouve dans `System32` et il est lancé par `services.exe`.',
    },
    {
      q: 'Quelle règle résiste le mieux au contournement ?',
      options: [
        '`Image` se termine par `mimikatz.exe`',
        'Le hash d’une version de Mimikatz, complété par celui de toutes ses versions publiques et de ses variantes connues',
        'Lecture de la mémoire de `lsass.exe` par un binaire non signé hors liste autorisée',
        'Le nom de domaine du C2',
      ],
      answer: 2,
      explain: "Cibler le comportement oblige l'attaquant à changer de technique. Un nom, un hash ou un domaine se changent en quelques minutes.",
    },
    {
      q: 'Une chasse ne révèle rien sur 90 jours. Que faire ?',
      options: [
        'La considérer comme inutile',
        'Documenter la requête, la couverture vérifiée et envisager une détection planifiée',
        'Supprimer les requêtes',
        'Déclarer le parc sain définitivement et retirer cette hypothèse du programme de chasse pour les années à venir',
      ],
      answer: 1,
      explain: "L'absence de résultat ne prouve pas l'absence d'attaquant, mais elle réduit l'incertitude. Encore faut-il avoir vérifié que les données étaient bien disponibles.",
    },
    {
      q: 'Quel artefact utiliser pour estimer le volume envoyé par une application sur le réseau ?',
      options: ['Prefetch', 'SRUM', 'ShellBags', 'Amcache'],
      answer: 1,
      explain: 'SRUM enregistre l’activité réseau par application pendant environ 30 jours, ce qui est très utile pour estimer une exfiltration.',
    },
  ],
}
