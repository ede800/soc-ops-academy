import type { Module } from '../../types'
import { code, h, info, p, r, table, tip, warn } from '../blocks'

export const m5: Module = {
  id: 'siem-sigma',
  number: 5,
  title: 'Requêtage SIEM : KQL, SPL et règles Sigma',
  tier: 'N2',
  summary:
    "Les deux langages que l'on croise le plus souvent en SOC, côte à côte, puis l'écriture de règles Sigma portables, testées et réalistes.",
  objectives: [
    'Traduire une question d’enquête en requête KQL et SPL',
    'Filtrer, agréger, joindre et mesurer',
    'Lire et écrire une règle Sigma complète',
    'Réduire les faux positifs sans créer d’angle mort',
  ],
  sections: [
    {
      id: 'bases',
      title: 'KQL et SPL côte à côte',
      blocks: [
        table(
          ['Besoin', 'KQL (Sentinel, Defender)', 'SPL (Splunk)'],
          ['Sélectionner la source', '`SecurityEvent`', '`index=wineventlog`'],
          ['Période', '`| where TimeGenerated > ago(24h)`', '`earliest=-24h`'],
          ['Filtrer', '`| where EventID == 4625`', '`EventCode=4625`'],
          ['Contient (mot entier)', '`has "powershell"`', '`powershell`'],
          ['Contient (sous-chaîne)', '`contains "power"`', '`*power*`'],
          ['Agréger', '`| summarize count() by Account`', '`| stats count by Account`'],
          ['Valeurs distinctes', '`dcount(Computer)`', '`dc(host)`'],
          ['Colonnes', '`| project A, B`', '`| table A B`'],
          ['Calculer', '`| extend x = a + b`', '`| eval x = a + b`'],
          ['Trier', '`| order by c desc`', '`| sort - c`'],
          ['Limiter', '`| take 10`', '`| head 10`'],
          ['Filtrer après agrégat', '`| where count_ > 10`', '`| where count > 10`'],
          ['Tranches de temps', '`bin(TimeGenerated, 1h)`', '`| bin _time span=1h`'],
          ['Regex', '`matches regex`, `extract()`', '`| rex field=x "(?<n>...)"`'],
        ),
        h('Les exemples de référence'),
        code('kql', 'KQL : brute-force', r`
SecurityEvent
| where EventID == 4625
| summarize count() by Account, IpAddress
| where count_ > 10
`),
        code('spl', 'SPL : PowerShell encodé', r`
index=windows EventCode=1 (Image="*\\powershell.exe" AND CommandLine="*-enc*")
| stats count by host, user, CommandLine
`),
        warn('Ce SPL contient un piège réel', "`*-enc*` correspond aussi à `-Encoding UTF8`, très fréquent dans les scripts d'administration. Et il rate `-e`, `-ec` ou `-EncodedCommand` abrégés autrement. Le simulateur d'alertes contient un cas réel fondé sur ce faux positif. Une version plus robuste figure ci-dessous."),
        code('spl', 'SPL : version robuste', r`
index=windows EventCode=1 (Image="*\\powershell.exe" OR Image="*\\pwsh.exe")
| regex CommandLine="(?i)\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[A-Za-z0-9+/=]{16,}"
| stats count earliest(_time) as first latest(_time) as last by host, user, ParentImage, CommandLine
`),
        code('kql', 'KQL : équivalent Defender', r`
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[A-Za-z0-9+/=]{16,}"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
`),
        tip('`has` plutôt que `contains` en KQL', "`has` s'appuie sur l'index de termes et il est bien plus rapide. Réservez `contains` aux cas où vous cherchez vraiment un fragment de mot. De même, en SPL, placez tous les filtres possibles avant le premier `|`."),
      ],
    },
    {
      id: 'avance',
      title: 'Requêtes d’enquête avancées',
      blocks: [
        h('Password spraying : une IP, plusieurs comptes'),
        code('kql', 'KQL', r`
SigninLogs
| where TimeGenerated > ago(1h) and ResultType in ("50126", "50053")
| summarize Comptes = dcount(UserPrincipalName), Tentatives = count() by IPAddress
| where Comptes > 10
| order by Comptes desc
`),
        code('spl', 'SPL', r`
index=wineventlog EventCode=4625 earliest=-1h
| stats dc(Account_Name) as comptes count as tentatives by Source_Network_Address
| where comptes > 10
| sort - comptes
`),
        h('Échecs suivis d’un succès : la corrélation à connaître'),
        code('kql', 'KQL : join', r`
let echecs = SecurityEvent
| where EventID == 4625
| summarize Echecs = count(), DernierEchec = max(TimeGenerated) by IpAddress, Account
| where Echecs > 10;
SecurityEvent
| where EventID == 4624
| join kind=inner echecs on IpAddress, Account
| where TimeGenerated > DernierEchec
| project TimeGenerated, Computer, Account, IpAddress, Echecs, LogonType
`),
        code('spl', 'SPL : stats conditionnelles', r`
index=wineventlog (EventCode=4625 OR EventCode=4624)
| stats count(eval(EventCode=4625)) as echecs count(eval(EventCode=4624)) as succes
        min(eval(if(EventCode=4624, _time, null()))) as premier_succes
        max(eval(if(EventCode=4625, _time, null()))) as dernier_echec
  by Source_Network_Address Account_Name
| where echecs > 10 AND succes > 0
`),
        h('Parent et enfant : Office qui lance un shell'),
        code('kql', 'KQL', r`
DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
`),
        code('spl', 'SPL', r`
index=sysmon EventCode=1
  (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\powerpnt.exe" OR ParentImage="*\\outlook.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe")
| table _time host User ParentImage Image CommandLine
`),
        h('Stacking : ce qui est rare est intéressant'),
        code('kql', 'KQL : binaires rares dans le parc', r`
DeviceProcessEvents
| where Timestamp > ago(7d)
| summarize Machines = dcount(DeviceName), Executions = count() by SHA256, FileName
| where Machines <= 2
| order by Executions desc
`),
        code('spl', 'SPL : tstats, beaucoup plus rapide (modèle de données CIM)', r`
| tstats count dc(Processes.dest) as machines from datamodel=Endpoint.Processes by Processes.process_name
| where machines <= 2
| sort - count
`),
        info('Bonnes pratiques', "Limitez la période dès la première ligne. Testez sur 24 h avant d'élargir. Nommez vos colonnes pour que la requête se relise. Enregistrez celles qui fonctionnent : une bonne requête d'enquête est souvent une future règle de détection."),
      ],
    },
    {
      id: 'sigma',
      title: 'Règles Sigma',
      blocks: [
        p("Sigma est à la détection sur logs ce que YARA est aux fichiers : un format YAML indépendant du SIEM, converti ensuite en KQL, SPL ou Elastic. Une règle écrite une fois peut suivre votre organisation d'un SIEM à l'autre."),
        code('yaml', 'Une règle complète', r`
title: Office lance un interpréteur de commandes
id: 1d9c2a53-6c2e-4f55-9a11-8f2b6f0c7a10
status: stable
description: Détecte un processus Office lançant un shell ou un LOLBin, schéma typique d'une macro malveillante.
references:
  - https://attack.mitre.org/techniques/T1204/002/
author: SOC Ops Academy
date: 2026-03-12
tags:
  - attack.execution
  - attack.t1204.002
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
      - '\POWERPNT.EXE'
      - '\OUTLOOK.EXE'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
  filter_addin:
    ParentCommandLine|contains: '\Office16\ADDINS\ERP-Connecteur\'
  condition: selection_parent and selection_child and not filter_addin
falsepositives:
  - Compléments Office légitimes appelant un script
level: high
`),
        table(
          ['Champ', 'Rôle'],
          ['`title`, `id`', 'Nom lisible et UUID stable pour le suivi des versions'],
          ['`status`', '`experimental`, `test` ou `stable`'],
          ['`logsource`', 'Type de log : `category` et `product`, ou `service`'],
          ['`detection`', 'Un ou plusieurs blocs de sélection et de filtre'],
          ['`condition`', 'Combinaison logique des blocs'],
          ['`falsepositives`', 'Faux positifs connus : cela aide vraiment le N1'],
          ['`level`', '`informational`, `low`, `medium`, `high` ou `critical`'],
          ['`tags`', 'Lien vers ATT&CK'],
        ),
        h('Modificateurs et logique'),
        table(
          ['Syntaxe', 'Effet'],
          ['`|contains`, `|startswith`, `|endswith`', 'Sous-chaîne, début, fin'],
          ['`|all`', 'Toutes les valeurs de la liste doivent correspondre (par défaut : une seule)'],
          ['`|re`', 'Expression régulière'],
          ['`|base64offset|contains`', 'Cherche une chaîne encodée en Base64, quel que soit le décalage'],
          ['`|cidr`', 'Plage réseau'],
          ['Clé à plusieurs valeurs', 'OU entre les valeurs'],
          ['Plusieurs clés dans un bloc', 'ET entre les clés'],
          ['`1 of selection_*`', 'Au moins un bloc correspondant au motif'],
          ['`all of them`', 'Tous les blocs'],
        ),
        code('yaml', 'Détection LSASS', r`
title: Accès suspect à LSASS
status: test
logsource:
  category: process_access
  product: windows
detection:
  selection:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
  filter_known:
    SourceImage|startswith:
      - 'C:\Program Files\Windows Defender\'
      - 'C:\ProgramData\Microsoft\Windows Defender\'
      - 'C:\Windows\System32\'
  condition: selection and not filter_known
level: high
tags:
  - attack.credential_access
  - attack.t1003.001
`),
        code('bash', 'Conversion avec sigma-cli', r`
pip install sigma-cli
sigma plugin install splunk
sigma plugin install kusto
sigma convert -t splunk -p sysmon regle.yml
sigma convert -t kusto -p microsoft_xdr regle.yml
`),
        warn('Attention aux filtres trop larges', "`SourceImage|contains: 'Defender'` permet à un attaquant de passer inaperçu avec `C:\\Temp\\Defender\\x.exe`. Une exclusion doit être aussi précise que possible : chemin complet, signature, hôte. Chaque exclusion est un angle mort que vous créez volontairement : documentez-la."),
        tip('Ne partez pas de zéro', 'Le dépôt `SigmaHQ/sigma` contient des milliers de règles maintenues par la communauté. Lisez-les, adaptez-les à votre parc et testez-les avant toute mise en production.'),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['Opération', 'KQL', 'SPL'],
      ['Compter', '`summarize count() by x`', '`stats count by x`'],
      ['Distinct', '`dcount(x)`', '`dc(x)`'],
      ['Ensemble', '`make_set(x)`', '`values(x)`'],
      ['Premier / dernier', '`min(t)` / `max(t)`', '`earliest(t)` / `latest(t)`'],
      ['Série temporelle', '`bin(t, 1h)`', '`timechart span=1h`'],
      ['Jointure', '`join kind=inner`', '`stats ... by clé` (préférable à `join`)'],
      ['Regex', '`extract(@"re", 1, x)`', '`rex field=x "(?<n>re)"`'],
      ['Multi-valeurs', '`mv-expand`', '`mvexpand`'],
    ),
    code('yaml', 'Squelette Sigma', r`
title:
id:
status: experimental
description:
author:
date:
tags:
  - attack.
logsource:
  category:
  product:
detection:
  selection:
    Champ|modificateur: valeur
  filter:
    Champ: valeur
  condition: selection and not filter
falsepositives:
  -
level: medium
`),
  ],
  quiz: [
    {
      q: 'Quel est le problème de ce filtre ?',
      evidence: { lang: 'spl', code: 'index=windows EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"' },
      options: [
        'Il est trop lent à cause de `index`',
        'Il déclenche aussi sur `-Encoding`, et rate des formes abrégées comme `-e`',
        'Sysmon ne journalise pas PowerShell',
        'EventCode=1 correspond à une connexion réseau dans Sysmon : il faudrait utiliser l’événement 3 pour ce filtre',
      ],
      answer: 1,
      explain: 'La sous-chaîne `-enc` correspond à `-Encoding`, et PowerShell accepte des abréviations. Une regex avec une valeur Base64 est plus fiable.',
    },
    {
      q: 'Quelle requête détecte le mieux un password spraying ?',
      options: [
        '`summarize count() by Account`',
        '`summarize dcount(Account) by IpAddress | where dcount_Account > 10`',
        '`summarize count() by Computer`',
        '`take 10`',
      ],
      answer: 1,
      explain: 'Le spraying teste peu de mots de passe sur beaucoup de comptes : le signal est le nombre de **comptes distincts** par source. Un brute-force classique, lui, compte les tentatives par compte.',
    },
    {
      q: 'Quel est l’équivalent SPL de `summarize dcount(Computer) by Account` ?',
      options: ['`stats dc(host) by Account`', '`stats count by host`', '`dedup host`', '`table host`'],
      answer: 0,
      explain: '`dc()` compte les valeurs distinctes, comme `dcount()` en KQL.',
    },
    {
      q: 'Dans une règle Sigma, comment se combinent deux clés au sein du même bloc de sélection ?',
      evidence: { lang: 'yaml', code: "selection:\n  Image|endswith: '\\cmd.exe'\n  ParentImage|endswith: '\\winword.exe'" },
      options: ['OU', 'ET', 'NON', 'Cela dépend du SIEM'],
      answer: 1,
      explain: 'Les clés d’un même bloc sont en ET. Les valeurs d’une même liste sont en OU, sauf avec `|all`.',
    },
    {
      q: 'Pourquoi `filter: SourceImage|contains: "Defender"` est-il dangereux ?',
      options: [
        'Il ralentit le SIEM',
        'Un attaquant peut créer `C:\\Temp\\Defender\\x.exe` et échapper à la règle',
        'Defender n’accède jamais à LSASS',
        'Le modificateur n’existe pas dans Sigma : seul `endswith` est accepté sur le champ `SourceImage`',
      ],
      answer: 1,
      explain: 'Une exclusion doit être précise : chemin complet, voire signature. Un `contains` sur un mot offre un contournement facile.',
    },
    {
      q: 'Que renvoie cette requête ?',
      evidence: { lang: 'kql', code: 'DeviceProcessEvents\n| where Timestamp > ago(7d)\n| summarize Machines = dcount(DeviceName) by SHA256, FileName\n| where Machines <= 2' },
      options: [
        'Les binaires les plus répandus',
        'Les binaires vus sur au plus deux machines : du stacking pour trouver ce qui est rare',
        'Les comptes admin',
        'Les connexions réseau ouvertes par chaque binaire, triées par machine et regroupées par volume de données',
      ],
      answer: 1,
      explain: 'Le stacking part d’une idée simple : un outil d’attaque est rare par rapport aux logiciels installés partout.',
    },
    {
      q: 'Quelle différence entre `has` et `contains` en KQL ?',
      options: [
        'Aucune',
        '`has` cherche un terme entier et utilise l’index ; `contains` cherche une sous-chaîne et il est plus lent',
        '`has` est sensible à la casse, pas `contains`, et les deux opérateurs parcourent la même colonne à la même vitesse',
        '`contains` est réservé à Defender',
      ],
      answer: 1,
      explain: 'Préférez `has` dès que vous cherchez un mot entier : les gains de performance sont importants sur de gros volumes.',
    },
  ],
}
