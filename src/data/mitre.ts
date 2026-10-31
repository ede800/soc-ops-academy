import type { Technique } from '../types'
import { r } from './blocks'

export const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Credential Access',
  'Lateral Movement',
  'Command and Control',
  'Exfiltration',
]

export const techniques: Technique[] = [
  // Initial Access
  {
    id: 'T1566.001',
    name: 'Phishing : pièce jointe',
    tactic: 'Initial Access',
    how: "Envoi d'un document à macros, d'un ISO, d'un LNK ou d'un HTA qui exécute une charge à l'ouverture.",
    logs: ['Passerelle mail', 'Sysmon 1, 11', 'EmailAttachmentInfo'],
    kql: r`EmailAttachmentInfo
| where Timestamp > ago(7d)
| where FileType in~ ("iso", "img", "lnk", "hta", "docm", "xlsm", "one", "vbs", "js")
| join kind=inner EmailEvents on NetworkMessageId
| where DeliveryAction == "Delivered"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256`,
    spl: r`index=mail attachment_ext IN (iso, img, lnk, hta, docm, xlsm, one, vbs, js) action=delivered
| stats count values(recipient) as destinataires by sender, attachment_name, file_hash`,
    falsePositives: 'Macros métier légitimes : surtout en finance. Conservez une liste des expéditeurs autorisés, réduite et revue.',
  },
  {
    id: 'T1566.002',
    name: 'Phishing : lien',
    tactic: 'Initial Access',
    how: 'Lien vers une fausse page ou un proxy AiTM (Evilginx) qui relaie la vraie authentification et vole le jeton de session.',
    logs: ['UrlClickEvents', 'SigninLogs', 'Proxy'],
    kql: r`UrlClickEvents
| where Timestamp > ago(1d) and ActionType == "ClickAllowed"
| join kind=inner (SigninLogs | where ResultType == 0 | project SigninTime = TimeGenerated, AccountUpn = UserPrincipalName, IPAddress, UserAgent) on AccountUpn
| where SigninTime between (Timestamp .. (Timestamp + 10m))
| project Timestamp, AccountUpn, Url, SigninTime, IPAddress, UserAgent`,
    spl: r`index=proxy url="*login*" http_method=POST NOT dest_domain IN (microsoftonline.com, live.com, office.com)
| stats count values(url) as urls by src_user, dest_domain`,
    falsePositives: 'SSO de partenaires et portails légitimes : liste d’autorisation par domaine exact.',
  },
  {
    id: 'T1190',
    name: 'Exploitation d’une application exposée',
    tactic: 'Initial Access',
    how: 'Exploitation d’une vulnérabilité (VPN, serveur web, messagerie) pour obtenir une exécution de code.',
    logs: ['WAF', 'access.log', 'EDR', 'W3CIISLog'],
    kql: r`DeviceProcessEvents
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd.exe", "tomcat9.exe", "nginx.exe", "java.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "whoami.exe", "net.exe", "certutil.exe", "bitsadmin.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
    spl: r`index=web status=200 (uri_query="*UNION*SELECT*" OR uri_query="*../..*" OR uri_query="*jndi:*" OR uri_query="*/etc/passwd*")
| stats count values(uri_path) as chemins by src_ip, host`,
    falsePositives: 'Scanners de vulnérabilités autorisés, et certaines applications Java qui lancent des scripts.',
  },
  {
    id: 'T1078',
    name: 'Comptes valides',
    tactic: 'Initial Access',
    how: 'Identifiants achetés, volés par infostealer ou devinés, puis utilisés sur VPN ou M365.',
    logs: ['SigninLogs', '4624', 'Logs VPN'],
    kql: r`SigninLogs
| where TimeGenerated > ago(14d) and ResultType == 0
| summarize Pays = make_set(Location, 10), NbPays = dcount(Location), IPs = dcount(IPAddress) by UserPrincipalName, bin(TimeGenerated, 1h)
| where NbPays > 1`,
    spl: r`index=vpn action=success
| iplocation src_ip
| bin _time span=1h
| stats dc(Country) as pays values(Country) as liste by user, _time
| where pays > 1`,
    falsePositives: 'VPN personnels, voyages et sorties Internet mobiles.',
  },
  // Execution
  {
    id: 'T1059.001',
    name: 'PowerShell',
    tactic: 'Execution',
    how: 'Charges encodées, téléchargement en mémoire (`IEX`, `DownloadString`), contournement de la politique d’exécution.',
    logs: ['Sysmon 1', '4104 (Script Block)', '4688', 'DeviceProcessEvents'],
    kql: r`DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s[-/]e(c|n|nc|nco|ncod|ncode|ncoded|ncodedc\w*)?\s+[A-Za-z0-9+/=]{16,}"
   or ProcessCommandLine has_any ("DownloadString", "FromBase64String", "IEX", "Invoke-Expression")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine`,
    spl: r`index=wineventlog source="*PowerShell/Operational*" EventCode=4104
  (ScriptBlockText="*DownloadString*" OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*VirtualAlloc*")
| table _time host UserID ScriptBlockText`,
    falsePositives: 'SCCM, Intune et scripts d’administration : surtout leurs parents et signatures. `-Encoding` n’est pas `-EncodedCommand`.',
  },
  {
    id: 'T1204.002',
    name: 'Exécution par l’utilisateur : fichier malveillant',
    tactic: 'Execution',
    how: 'La victime ouvre un document ou un raccourci. Office, l’explorateur ou le lecteur de scripts lancent alors la charge.',
    logs: ['Sysmon 1', 'DeviceProcessEvents'],
    kql: r`DeviceProcessEvents
| where InitiatingProcessFileName in~ ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "onenote.exe")
| where FileName in~ ("cmd.exe", "powershell.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=1 (ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe" OR ParentImage="*\\outlook.exe")
  (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe" OR Image="*\\mshta.exe" OR Image="*\\rundll32.exe")
| table _time host User ParentImage Image CommandLine`,
    falsePositives: 'Compléments Office : ajoutez des exclusions par chemin complet.',
  },
  {
    id: 'T1047',
    name: 'WMI',
    tactic: 'Execution',
    how: 'Exécution distante sans fichier via `wmic /node:x process call create`.',
    logs: ['Sysmon 1', '4688', 'WMI-Activity'],
    kql: r`DeviceProcessEvents
| where InitiatingProcessFileName =~ "wmiprvse.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "rundll32.exe", "mshta.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=1 ParentImage="*\\WmiPrvSE.exe" (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\rundll32.exe")
| table _time host User Image CommandLine`,
    falsePositives: 'Outils de gestion, SCCM et inventaires.',
  },
  // Persistence
  {
    id: 'T1053.005',
    name: 'Tâche planifiée',
    tactic: 'Persistence',
    how: '`schtasks /create` pour relancer une charge au démarrage ou à intervalle régulier.',
    logs: ['4698', '4702', 'Sysmon 1', 'TaskScheduler 106'],
    kql: r`SecurityEvent
| where EventID == 4698
| extend TaskContent = tostring(EventData)
| where TaskContent has_any ("powershell", "cmd.exe", "mshta", "rundll32", "\\Users\\", "\\Temp\\", "\\ProgramData\\")
| project TimeGenerated, Computer, SubjectUserName, TaskContent`,
    spl: r`index=wineventlog EventCode=4698 (Task_Content="*powershell*" OR Task_Content="*\\Users\\*" OR Task_Content="*\\Temp\\*" OR Task_Content="*mshta*")
| table _time host Account_Name Task_Name Task_Content`,
    falsePositives: 'Mises à jour de navigateurs, logiciels métier : analysez le chemin et la signature.',
  },
  {
    id: 'T1543.003',
    name: 'Service Windows',
    tactic: 'Persistence',
    how: 'Création d’un service qui lance une charge avec le compte SYSTEM. PsExec en crée également un.',
    logs: ['7045', '4697', 'Sysmon 13'],
    kql: r`SecurityEvent
| where EventID == 4697
| extend Path = extract(@'ServiceFileName">([^<]+)', 1, EventData), Name = extract(@'ServiceName">([^<]+)', 1, EventData)
| where Path has_any ("\\Users\\", "\\Temp\\", "\\ProgramData\\", "cmd ", "powershell", "%COMSPEC%")
| project TimeGenerated, Computer, SubjectUserName, Name, Path`,
    spl: r`index=wineventlog EventCode=7045 (Service_File_Name="*\\Users\\*" OR Service_File_Name="*\\Temp\\*" OR Service_File_Name="*powershell*" OR Service_File_Name="*COMSPEC*")
| table _time host Service_Name Service_File_Name`,
    falsePositives: 'Installateurs qui placent temporairement un service dans `Temp`.',
  },
  {
    id: 'T1547.001',
    name: 'Clés Run et dossier Startup',
    tactic: 'Persistence',
    how: 'Ajout d’une valeur sous `CurrentVersion\\Run` pour relancer la charge à l’ouverture de session.',
    logs: ['Sysmon 13', 'DeviceRegistryEvents'],
    kql: r`DeviceRegistryEvents
| where ActionType == "RegistryValueSet" and RegistryKey has @"\CurrentVersion\Run"
| where RegistryValueData has_any ("AppData", "Temp", "Public", "ProgramData", "powershell", "rundll32", "mshta")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueName, RegistryValueData`,
    spl: r`index=sysmon EventCode=13 TargetObject="*\\CurrentVersion\\Run*"
  (Details="*AppData*" OR Details="*Temp*" OR Details="*Public*" OR Details="*powershell*" OR Details="*rundll32*")
| table _time host Image TargetObject Details`,
    falsePositives: 'Teams, OneDrive, Zoom et Discord s’installent parfois dans AppData : vérifiez le binaire exact.',
  },
  {
    id: 'T1505.003',
    name: 'Web shell',
    tactic: 'Persistence',
    how: 'Dépôt d’un script sur un serveur web, piloté ensuite via des requêtes HTTP.',
    logs: ['access.log', 'auditd', 'W3CIISLog', 'Sysmon 11'],
    kql: r`DeviceFileEvents
| where FolderPath has_any (@"\inetpub\wwwroot", "/var/www")
| where FileName endswith ".aspx" or FileName endswith ".ashx" or FileName endswith ".php" or FileName endswith ".jsp"
| where InitiatingProcessFileName in~ ("w3wp.exe", "httpd", "apache2", "nginx", "php-fpm", "java.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, FolderPath, FileName`,
    spl: r`index=web status=200 uri_path="*/uploads/*" (uri_path="*.php" OR uri_path="*.aspx" OR uri_path="*.jsp")
| stats count values(http_user_agent) as ua by src_ip, uri_path`,
    falsePositives: 'Déploiements applicatifs. Corrélez avec une fenêtre de mise en production.',
  },
  {
    id: 'T1136.001',
    name: 'Création de compte local',
    tactic: 'Persistence',
    how: '`net user x /add` suivi d’un ajout au groupe Administrateurs.',
    logs: ['4720', '4732', 'Sysmon 1', 'auth.log'],
    kql: r`SecurityEvent
| where EventID in (4720, 4732)
| summarize Evenements = make_set(EventID), Debut = min(TimeGenerated) by Computer, SubjectUserName, bin(TimeGenerated, 15m)
| where array_length(Evenements) == 2`,
    spl: r`index=wineventlog EventCode IN (4720, 4732)
| bin _time span=15m
| stats values(EventCode) as codes by _time host Subject_Account_Name
| where mvcount(codes) = 2`,
    falsePositives: 'Opérations IT : recoupez toujours avec un ticket approuvé.',
  },
  // Privilege Escalation
  {
    id: 'T1055',
    name: 'Injection de processus',
    tactic: 'Privilege Escalation',
    how: 'Écriture de code dans un autre processus puis `CreateRemoteThread`, pour hériter de son contexte.',
    logs: ['Sysmon 8', 'Sysmon 10', 'DeviceEvents'],
    kql: r`DeviceEvents
| where ActionType == "CreateRemoteThreadApiCall"
| where InitiatingProcessFolderPath !startswith @"C:\Windows\System32" and InitiatingProcessFolderPath !startswith @"C:\Program Files"
| project Timestamp, DeviceName, InitiatingProcessFileName, FileName, InitiatingProcessCommandLine`,
    spl: r`index=sysmon EventCode=8 NOT (SourceImage="C:\\Windows\\System32\\*" OR SourceImage="C:\\Program Files*")
| stats count by SourceImage TargetImage StartFunction host`,
    falsePositives: 'EDR, antivirus, outils de débogage, certains navigateurs.',
  },
  {
    id: 'T1548.002',
    name: 'Contournement de l’UAC',
    tactic: 'Privilege Escalation',
    how: 'Détournement d’un binaire auto-élevé comme `fodhelper.exe` via une clé de registre utilisateur.',
    logs: ['Sysmon 1', 'Sysmon 13'],
    kql: r`DeviceRegistryEvents
| where RegistryKey has_any (@"ms-settings\Shell\Open\command", @"mscfile\Shell\Open\command", @"exefile\Shell\Runas\command")
| project Timestamp, DeviceName, InitiatingProcessFileName, RegistryKey, RegistryValueData`,
    spl: r`index=sysmon EventCode=1 (ParentImage="*\\fodhelper.exe" OR ParentImage="*\\eventvwr.exe" OR ParentImage="*\\computerdefaults.exe" OR ParentImage="*\\sdclt.exe")
| table _time host User ParentImage Image CommandLine`,
    falsePositives: 'Rares : ces binaires lancent peu d’enfants.',
  },
  {
    id: 'T1068',
    name: 'Exploitation pour élévation',
    tactic: 'Privilege Escalation',
    how: 'Exploitation d’une vulnérabilité locale ou d’un pilote vulnérable (BYOVD) pour obtenir SYSTEM.',
    logs: ['Sysmon 6', 'Sysmon 1', 'DeviceEvents'],
    kql: r`DeviceProcessEvents
| where AccountSid == "S-1-5-18"
| where InitiatingProcessAccountSid != "S-1-5-18" and InitiatingProcessIntegrityLevel in ("Medium", "Low")
| where InitiatingProcessFileName !in~ ("msiexec.exe", "consent.exe", "svchost.exe")
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=6 (Signed=false OR SignatureStatus!=Valid)
| stats count by ImageLoaded Signature Hashes host`,
    falsePositives: 'Mécanismes de mise à jour légitimes : comparez aux listes de pilotes vulnérables (LOLDrivers).',
  },
  // Credential Access
  {
    id: 'T1003.001',
    name: 'Dump de LSASS',
    tactic: 'Credential Access',
    how: 'Lecture de la mémoire de `lsass.exe` : Mimikatz, `comsvcs.dll MiniDump`, `procdump`.',
    logs: ['Sysmon 10', 'Sysmon 1', 'Sysmon 11'],
    kql: r`DeviceProcessEvents
| where ProcessCommandLine has_all ("comsvcs", "MiniDump") or (ProcessCommandLine has "procdump" and ProcessCommandLine has "lsass") or ProcessCommandLine has "sekurlsa::"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=10 TargetImage="*\\lsass.exe" GrantedAccess IN ("0x1010", "0x1410", "0x1fffff")
  NOT (SourceImage="C:\\Program Files\\Windows Defender\\*" OR SourceImage="C:\\ProgramData\\Microsoft\\Windows Defender\\*")
| table _time host SourceImage GrantedAccess CallTrace`,
    falsePositives: 'Antivirus, EDR et agents de supervision : excluez par chemin complet et signature.',
  },
  {
    id: 'T1003.006',
    name: 'DCSync',
    tactic: 'Credential Access',
    how: 'Le compte demande la réplication comme un DC : tous les hash, y compris `krbtgt`.',
    logs: ['4662 sur les DC', 'Zeek DCE-RPC'],
    kql: r`SecurityEvent
| where EventID == 4662 and AccessMask == "0x100"
| where Properties has_any ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
| where Account !endswith "$"
| project TimeGenerated, Computer, Account, Properties`,
    spl: r`index=wineventlog EventCode=4662 Access_Mask=0x100
  (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")
  Account_Name!="*$" Account_Name!="MSOL_*"
| table _time host Account_Name Properties`,
    falsePositives: 'Azure AD Connect (`MSOL_*`) et certains outils d’audit : contrôlez aussi le serveur source.',
  },
  {
    id: 'T1558.003',
    name: 'Kerberoasting',
    tactic: 'Credential Access',
    how: 'Demander des tickets pour des comptes de service, puis casser leur mot de passe hors ligne.',
    logs: ['4769 sur les DC', 'Sysmon 1'],
    kql: r`SecurityEvent
| where EventID == 4769
| parse EventData with * 'TargetUserName">' User '<' * 'ServiceName">' Service '<' * 'TicketEncryptionType">' Enc '<' *
| where Enc == "0x17" and Service !endswith "$" and Service != "krbtgt"
| summarize Spn = dcount(Service) by User, bin(TimeGenerated, 10m)
| where Spn > 5`,
    spl: r`index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$" Service_Name!="krbtgt"
| bin _time span=10m
| stats dc(Service_Name) as spn by _time Account_Name Client_Address
| where spn > 5`,
    falsePositives: 'Applications anciennes sans AES : leur volume reste faible et stable.',
  },
  {
    id: 'T1558.004',
    name: 'AS-REP Roasting',
    tactic: 'Credential Access',
    how: 'Récupérer un AS-REP pour les comptes configurés sans pré-authentification Kerberos, puis le casser hors ligne.',
    logs: ['4768 sur les DC'],
    kql: r`SecurityEvent
| where EventID == 4768
| parse EventData with * 'TargetUserName">' User '<' * 'TicketEncryptionType">' Enc '<' * 'PreAuthType">' PreAuth '<' *
| where PreAuth == "0" and Enc == "0x17"
| project TimeGenerated, Computer, User, IpAddress`,
    spl: r`index=wineventlog EventCode=4768 Pre_Authentication_Type=0 Ticket_Encryption_Type=0x17
| stats count values(Account_Name) as comptes by Client_Address`,
    falsePositives: 'Comptes anciens sans pré-authentification : à corriger, car ils restent exposés dans tous les cas.',
  },
  {
    id: 'T1110.003',
    name: 'Password spraying',
    tactic: 'Credential Access',
    how: 'Tester un mot de passe courant sur de nombreux comptes, lentement pour éviter le verrouillage.',
    logs: ['4625', 'SigninLogs', 'Logs VPN'],
    kql: r`SigninLogs
| where TimeGenerated > ago(1d) and ResultType in ("50126", "50053")
| summarize Comptes = dcount(UserPrincipalName), Tentatives = count() by IPAddress, bin(TimeGenerated, 1h)
| where Comptes > 10`,
    spl: r`index=wineventlog EventCode=4625 earliest=-24h
| bin _time span=1h
| stats dc(Account_Name) as comptes count as tentatives by _time Source_Network_Address
| where comptes > 10`,
    falsePositives: 'NAT d’entreprise, proxy et changement global de mot de passe.',
  },
  // Lateral Movement
  {
    id: 'T1021.001',
    name: 'RDP',
    tactic: 'Lateral Movement',
    how: 'Connexion bureau à distance avec des identifiants volés, entre postes ou depuis un serveur non prévu.',
    logs: ['4624 type 10', '1149', 'LocalSessionManager 21'],
    kql: r`SecurityEvent
| where EventID == 4624 and LogonType == 10
| where IpAddress !in ("10.10.1.5")
| summarize Cibles = dcount(Computer), Liste = make_set(Computer, 20) by TargetUserName, IpAddress
| order by Cibles desc`,
    spl: r`index=wineventlog EventCode=4624 Logon_Type=10 NOT Source_Network_Address="10.10.1.5"
| stats dc(host) as cibles values(host) as liste by Account_Name Source_Network_Address
| sort - cibles`,
    falsePositives: 'Support IT sans bastion : c’est un point à corriger en soi.',
  },
  {
    id: 'T1021.002',
    name: 'SMB et partages admin (PsExec)',
    tactic: 'Lateral Movement',
    how: 'Copie d’un binaire vers `ADMIN$` puis création d’un service (PSEXESVC).',
    logs: ['5140', '5145', '7045', '4624 type 3'],
    kql: r`SecurityEvent
| where EventID == 5145 and ShareName has_any ("ADMIN$", "C$")
| where RelativeTargetName endswith ".exe" or RelativeTargetName endswith ".dll"
| summarize Cibles = dcount(Computer), Fichiers = make_set(RelativeTargetName, 10) by SubjectUserName, IpAddress
| order by Cibles desc`,
    spl: r`index=wineventlog (EventCode=7045 Service_Name=PSEXESVC) OR (EventCode=5145 Share_Name="*ADMIN$" Relative_Target_Name="*.exe")
| stats dc(host) as cibles values(host) as liste by Account_Name Source_Address`,
    falsePositives: 'Déploiements IT par PsExec ou SCCM depuis des serveurs connus.',
  },
  {
    id: 'T1550.002',
    name: 'Pass-the-Hash',
    tactic: 'Lateral Movement',
    how: 'Réutiliser le hash NTLM volé, sans connaître le mot de passe.',
    logs: ['4624 type 3 NTLM', '4624 type 9', 'Sysmon 10'],
    kql: r`SecurityEvent
| where EventID == 4624
| where (LogonType == 9 and LogonProcessName has "seclogo") or (LogonType == 3 and AuthenticationPackageName == "NTLM" and TargetUserName !endswith "$")
| summarize Cibles = dcount(Computer) by TargetUserName, IpAddress, LogonType
| where Cibles > 3 or LogonType == 9`,
    spl: r`index=wineventlog EventCode=4624 ((Logon_Type=9 Logon_Process=seclogo) OR (Logon_Type=3 Authentication_Package=NTLM Account_Name!="*$"))
| stats dc(host) as cibles by Account_Name Source_Network_Address Logon_Type`,
    falsePositives: 'Type 9 : `runas /netonly` utilisé par les admins. NTLM : parc ancien, scanners.',
  },
  {
    id: 'T1021.006',
    name: 'WinRM',
    tactic: 'Lateral Movement',
    how: 'Exécution distante via PowerShell Remoting (`Enter-PSSession`, Evil-WinRM).',
    logs: ['Sysmon 1', '4624 type 3', 'WinRM Operational', 'Port 5985'],
    kql: r`DeviceProcessEvents
| where InitiatingProcessFileName =~ "wsmprovhost.exe"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=1 ParentImage="*\\wsmprovhost.exe"
| stats count values(CommandLine) as commandes by host User`,
    falsePositives: 'Administration à distance : vérifiez la source et le compte.',
  },
  // C2
  {
    id: 'T1071.001',
    name: 'C2 via HTTP(S)',
    tactic: 'Command and Control',
    how: 'Implant qui contacte son serveur à intervalles réguliers, parfois avec un profil imitant un CDN (Cobalt Strike).',
    logs: ['Proxy', 'Zeek conn et http', 'Sysmon 3'],
    kql: r`DeviceNetworkEvents
| where RemoteUrl != "" and Timestamp > ago(1d)
| order by DeviceName asc, RemoteUrl asc, Timestamp asc
| extend Delta = iff(prev(DeviceName) == DeviceName and prev(RemoteUrl) == RemoteUrl, datetime_diff('second', Timestamp, prev(Timestamp)), int(null))
| where isnotnull(Delta) and Delta > 0
| summarize Hits = count(), Avg = avg(Delta), Dev = stdev(Delta) by DeviceName, RemoteUrl, InitiatingProcessFileName
| where Hits > 50 and Dev / Avg < 0.2`,
    spl: r`index=proxy earliest=-24h
| sort 0 src dest _time
| streamstats current=f last(_time) as prev by src dest
| eval delta = _time - prev
| stats count avg(delta) as avg stdev(delta) as dev by src dest
| where count > 50 AND dev / avg < 0.2`,
    falsePositives: 'Mises à jour, télémétrie, agents : conservez une liste d’autorisation.',
  },
  {
    id: 'T1071.004',
    name: 'C2 via DNS',
    tactic: 'Command and Control',
    how: 'Ordres et données encodés dans des sous-domaines et des réponses TXT.',
    logs: ['Zeek dns.log', 'DnsEvents', 'Sysmon 22'],
    kql: r`DnsEvents
| where SubType == "LookupQuery"
| extend Parts = split(Name, ".")
| extend Root = strcat(Parts[array_length(Parts) - 2], ".", Parts[array_length(Parts) - 1])
| summarize Unique = dcount(Name), AvgLen = avg(strlen(Name)) by Root, ClientIP
| where Unique > 500 and AvgLen > 40`,
    spl: r`index=dns
| eval len = len(query)
| rex field=query "(?<root>[^.]+\.[^.]+)$"
| stats dc(query) as uniques avg(len) as moy values(record_type) as types by root src
| where uniques > 500 AND moy > 40`,
    falsePositives: 'Antivirus avec réputation DNS, CDN et télémétrie.',
  },
  {
    id: 'T1105',
    name: 'Transfert d’outils',
    tactic: 'Command and Control',
    how: 'Récupération de charges avec `certutil`, `bitsadmin`, `curl` ou `Invoke-WebRequest`.',
    logs: ['Sysmon 1, 3, 11', 'Proxy'],
    kql: r`DeviceProcessEvents
| where (FileName =~ "certutil.exe" and ProcessCommandLine has_any ("urlcache", "-decode", "verifyctl"))
   or (FileName =~ "bitsadmin.exe" and ProcessCommandLine has "/transfer")
   or (FileName in~ ("curl.exe", "wget.exe") and ProcessCommandLine has_any ("http://", "https://") and InitiatingProcessFileName !in~ ("msedge.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl: r`index=sysmon EventCode=1 ((Image="*\\certutil.exe" CommandLine="*urlcache*") OR (Image="*\\bitsadmin.exe" CommandLine="*/transfer*") OR (Image="*\\certutil.exe" CommandLine="*-decode*"))
| table _time host User Image CommandLine`,
    falsePositives: 'Scripts d’installation, développeurs avec `curl`.',
  },
  {
    id: 'T1219',
    name: 'Logiciel d’accès distant',
    tactic: 'Command and Control',
    how: 'AnyDesk, TeamViewer, Atera, ScreenConnect : signés, ils passent souvent les contrôles.',
    logs: ['Sysmon 1, 3, 22', 'Proxy', 'DeviceProcessEvents'],
    kql: r`DeviceProcessEvents
| where FileName in~ ("anydesk.exe", "teamviewer.exe", "screenconnect.clientservice.exe", "atera_agent.exe", "rustdesk.exe", "ngrok.exe", "tailscaled.exe")
| summarize Machines = dcount(DeviceName), Premier = min(Timestamp) by FileName, AccountName`,
    spl: r`index=sysmon EventCode=1 (Image="*\\anydesk.exe" OR Image="*\\teamviewer.exe" OR Image="*\\screenconnect*" OR Image="*\\rustdesk.exe" OR Image="*\\ngrok.exe")
| stats dc(host) as machines earliest(_time) as premier by Image User`,
    falsePositives: 'Support IT ou prestataire : recoupez avec l’outil officiel de l’entreprise.',
  },
  // Exfiltration
  {
    id: 'T1041',
    name: 'Exfiltration par le canal C2',
    tactic: 'Exfiltration',
    how: 'Envoi des données via le même canal que le C2, souvent découpé pour rester discret.',
    logs: ['Proxy', 'Zeek conn', 'SRUM'],
    kql: r`CommonSecurityLog
| where TimeGenerated > ago(1d) and DeviceAction !in ("deny", "drop")
| summarize Sent = sum(SentBytes), Recv = sum(ReceivedBytes) by SourceIP, DestinationHostName
| where Sent > 100000000 and Sent > Recv * 2
| order by Sent desc`,
    spl: r`index=proxy earliest=-24h
| stats sum(bytes_out) as sortants sum(bytes_in) as entrants by src dest
| where sortants > 100000000 AND sortants > entrants * 2
| sort - sortants`,
    falsePositives: 'Sauvegardes cloud, visioconférences et envois volumineux.',
  },
  {
    id: 'T1567.002',
    name: 'Exfiltration vers un cloud',
    tactic: 'Exfiltration',
    how: '`rclone`, MEGA ou stockage personnel, qui se fondent dans le trafic HTTPS légitime.',
    logs: ['Sysmon 1, 3', 'CASB', 'DLP'],
    kql: r`DeviceProcessEvents
| where FileName =~ "rclone.exe" or ProcessCommandLine has_any ("rclone", " mega:", "--transfers", "--config")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
    spl: r`index=proxy (dest="*mega.nz" OR dest="*mega.co.nz" OR dest="*dropboxapi.com" OR dest="*transfer.sh" OR dest="*anonfiles*") http_method IN (POST, PUT)
| stats sum(bytes_out) as sortants by src_user src dest
| sort - sortants`,
    falsePositives: 'Usage toléré d’un stockage personnel. La politique interne tranche.',
  },
  {
    id: 'T1048.003',
    name: 'Exfiltration par protocole non chiffré',
    tactic: 'Exfiltration',
    how: 'DNS, FTP, ICMP ou SMTP pour contourner le proxy web.',
    logs: ['Pare-feu', 'Zeek', 'DnsEvents'],
    kql: r`CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DestinationPort in (21, 22, 25, 53, 69, 465, 587, 990, 2222) and DeviceAction !in ("deny", "drop")
| where not(ipv4_is_private(DestinationIP))
| summarize Sent = sum(SentBytes) by SourceIP, DestinationIP, DestinationPort
| where Sent > 50000000
| order by Sent desc`,
    spl: r`index=firewall action=allowed dest_port IN (21, 22, 25, 53, 69, 465, 587, 990, 2222) NOT dest_ip IN (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
| stats sum(bytes_out) as sortants by src_ip dest_ip dest_port
| where sortants > 50000000`,
    falsePositives: 'Relais SMTP, transferts SFTP avec des partenaires.',
  },
]
