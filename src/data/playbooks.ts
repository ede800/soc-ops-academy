import type { Playbook } from '../types'
import { r } from './blocks'

export const playbooks: Playbook[] = [
  {
    id: 'm365-aitm',
    title: 'Phishing et compromission de compte M365 (AiTM, vol de jeton)',
    severity: 'Haute',
    sla: 'Confinement sous 30 minutes',
    trigger: 'Connexion anormale, alerte Entra ID Protection, règle de boîte suspecte, utilisateur qui signale avoir saisi ses identifiants',
    roles: 'N1 : qualification. N2 : exécution. Finance et juridique si fraude.',
    mitre: ['T1566.002', 'T1557', 'T1539', 'T1114.003', 'T1098'],
    phases: [
      {
        name: 'Identification',
        steps: [
          {
            title: 'Confirmer la session malveillante',
            detail: 'Cherchez une connexion réussie depuis une IP ou un client inhabituel, peu après le clic. Une MFA « satisfaite » ne disculpe pas le compte : un proxy AiTM la relaie.',
            code: {
              lang: 'kql',
              title: 'Connexions de l’utilisateur',
              code: r`SigninLogs
| where TimeGenerated > ago(7d) and UserPrincipalName == "user@contoso.example"
| where ResultType == 0
| project TimeGenerated, IPAddress, Location, AppDisplayName, ClientAppUsed, UserAgent, RiskLevelDuringSignIn, AuthenticationRequirement
| order by TimeGenerated desc`,
            },
          },
          {
            title: 'Trouver le message et les autres victimes',
            detail: 'Identifiez la campagne : même URL, même expéditeur ou même sujet. Combien de destinataires ? Qui a cliqué ?',
            code: {
              lang: 'kql',
              title: 'Portée de la campagne',
              code: r`UrlClickEvents
| where Timestamp > ago(7d) and Url has "domaine-phishing.example"
| summarize Clics = count() by AccountUpn, ActionType`,
            },
          },
          {
            title: 'Évaluer ce que l’attaquant a fait',
            detail: 'Lecture de mails, envois, téléchargements SharePoint, enregistrement d’un appareil ou d’une méthode MFA, consentement OAuth.',
            code: {
              lang: 'kql',
              title: 'Actions depuis l’IP suspecte',
              code: r`OfficeActivity
| where TimeGenerated > ago(7d) and UserId == "user@contoso.example" and ClientIP has "203.0.113.141"
| summarize Actions = count(), Premier = min(TimeGenerated), Dernier = max(TimeGenerated) by Operation`,
            },
            decision: 'Compte à privilèges ou rôle Entra sensible ? Si oui, escalade immédiate au N3 et au responsable SOC.',
          },
        ],
      },
      {
        name: 'Confinement',
        steps: [
          {
            title: 'Révoquer les sessions et jetons',
            detail: "Cette action invalide les jetons d'actualisation. Un jeton d'accès déjà émis peut rester valable jusqu'à son expiration (souvent environ 1 h) si l'application ne prend pas en charge CAE : envisagez un blocage temporaire du compte.",
            code: {
              lang: 'powershell',
              title: 'Microsoft Graph',
              code: r`Connect-MgGraph -Scopes "User.ReadWrite.All","User.RevokeSessions.All"
Update-MgUser -UserId user@contoso.example -AccountEnabled:$false
Revoke-MgUserSignInSession -UserId user@contoso.example`,
            },
          },
          {
            title: 'Réinitialiser le mot de passe et les méthodes MFA',
            detail: 'Passez en revue chaque méthode d’authentification et supprimez toute méthode ajoutée par l’attaquant. Réenrôlez avec une méthode résistante au phishing (FIDO2, Windows Hello).',
            code: {
              lang: 'powershell',
              title: 'Lister les méthodes',
              code: r`Get-MgUserAuthenticationMethod -UserId user@contoso.example
Get-MgUserRegisteredDevice -UserId user@contoso.example`,
            },
          },
          {
            title: 'Bloquer l’infrastructure',
            detail: 'Blocage de l’URL et du domaine sur proxy et Defender, IP de l’attaquant en accès conditionnel, purge des messages de la campagne.',
          },
        ],
      },
      {
        name: 'Éradication',
        steps: [
          {
            title: 'Supprimer les règles de boîte cachées',
            detail: "Les attaquants utilisent des noms comme `.` ou `..`, et déplacent les réponses vers `RSS Subscriptions`. `-IncludeHidden` n'est pas optionnel.",
            code: {
              lang: 'powershell',
              title: 'Exchange Online',
              code: r`Connect-ExchangeOnline
Get-InboxRule -Mailbox user@contoso.example -IncludeHidden |
  Select-Object Name,Enabled,MoveToFolder,ForwardTo,RedirectTo,SubjectContainsWords,DeleteMessage

Get-Mailbox user@contoso.example |
  Select-Object ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward

Remove-InboxRule -Mailbox user@contoso.example -Identity "<nom ou identifiant>"`,
            },
          },
          {
            title: 'Retirer les persistances applicatives',
            detail: 'Applications OAuth consenties, appareils enregistrés, délégations de boîte, droits ajoutés.',
            code: {
              lang: 'powershell',
              title: 'Vérifications',
              code: r`Get-MgUserOauth2PermissionGrant -UserId user@contoso.example
Get-MailboxPermission user@contoso.example | Where-Object { $_.User -notlike "NT AUTHORITY*" }`,
            },
          },
          {
            title: 'Traiter la fraude et les envois',
            detail: 'Si des messages ont été envoyés, prévenez les destinataires et la Finance : un faux RIB peut être payé en quelques heures. Purgez les messages internes.',
          },
        ],
      },
      {
        name: 'Clôture',
        steps: [
          {
            title: 'Réactiver sous surveillance',
            detail: 'Réactivez le compte après les nouvelles MFA, surveillez 72 h, et vérifiez qu’aucune nouvelle session anormale ne se présente.',
          },
          {
            title: 'Durcir et documenter',
            detail: 'Évaluez l’accès conditionnel (appareil conforme, MFA résistante), rédigez le rapport et informez le DPO si des données personnelles ont été lues.',
          },
        ],
      },
    ],
    closure: ['Aucune session de l’attaquant depuis 72 h', 'Règles et méthodes MFA vérifiées', 'Destinataires de la campagne traités', 'Décision DPO documentée'],
    pitfalls: ['Changer le mot de passe sans révoquer les sessions', 'Oublier `-IncludeHidden`', 'Ne regarder que l’utilisateur qui a signalé, et non les autres cliqueurs', 'Considérer que la MFA exclut la compromission'],
  },
  {
    id: 'malware-edr',
    title: 'Malware et alerte EDR sur un poste',
    severity: 'Haute',
    sla: 'Isolement sous 15 minutes',
    trigger: 'Alerte EDR confirmée, lignée anormale, callback C2',
    roles: 'N1 : qualification et isolement. N2 : collecte et analyse.',
    mitre: ['T1204.002', 'T1059.001', 'T1547.001', 'T1071.001'],
    phases: [
      {
        name: 'Identification',
        steps: [
          { title: 'Reconstituer la lignée et le point d’entrée', detail: 'Parent, ligne de commande, mail ou téléchargement d’origine, utilisateur, heure de la première exécution.' },
          {
            title: 'Chercher l’étendue',
            detail: 'Le SHA-256 et le C2 sont-ils présents sur d’autres hôtes ?',
            code: {
              lang: 'kql',
              title: 'Portée',
              code: r`union DeviceProcessEvents, DeviceFileEvents, DeviceImageLoadEvents
| where Timestamp > ago(30d) and SHA256 == "<sha256>"
| summarize Premier = min(Timestamp), Dernier = max(Timestamp), Evenements = count() by DeviceName`,
            },
            decision: 'Plus d’un hôte ou compte à privilèges utilisé sur le poste ? Passez au playbook Ransomware / mouvement latéral.',
          },
        ],
      },
      {
        name: 'Confinement',
        steps: [
          {
            title: 'Isoler via l’EDR',
            detail: "L'isolement EDR coupe le réseau tout en maintenant le lien avec la console. N'éteignez pas la machine : la mémoire est une preuve.",
            code: {
              lang: 'text',
              title: 'API Defender for Endpoint',
              code: r`POST https://api.securitycenter.microsoft.com/api/machines/{id}/isolate
{ "Comment": "INC-20418 : malware confirmé", "IsolationType": "Full" }`,
            },
          },
          {
            title: 'Capturer la mémoire et le triage',
            detail: 'Mémoire d’abord, disque ensuite. Écrivez sur un support externe ou un partage dédié, jamais sur le disque C:.',
            code: {
              lang: 'powershell',
              title: 'Collecte',
              code: r`# Mémoire
winpmem_mini_x64.exe E:\INC-20418\mem.raw

# Triage KAPE
kape.exe --tsource C: --tdest E:\INC-20418\triage --target !SANS_Triage --vhdx %m

# Empreinte de la preuve
Get-FileHash E:\INC-20418\mem.raw -Algorithm SHA256`,
            },
          },
          {
            title: 'Bloquer le SHA-256 et le C2',
            detail: 'Indicateur EDR (blocage du hash), domaine et IP sur proxy et pare-feu. Un hash se contourne facilement : c’est une mesure immédiate, pas la solution définitive.',
          },
          {
            title: 'Traiter le compte',
            detail: 'Réinitialisez le mot de passe de l’utilisateur, révoquez ses sessions, et considérez comme exposé tout identifiant utilisé sur ce poste.',
          },
        ],
      },
      {
        name: 'Éradication',
        steps: [
          {
            title: 'Identifier toute la persistance',
            detail: 'Clés Run, tâches, services, WMI, dossier Startup, DLL sideloading.',
            code: {
              lang: 'text',
              title: 'Velociraptor : artefacts utiles',
              code: `Windows.Sys.StartupItems
Windows.System.TaskScheduler
Windows.System.Services
Windows.Persistence.PermanentWMIEvents
Windows.KapeFiles.Targets`,
            },
          },
          { title: 'Réinstaller plutôt que nettoyer', detail: 'Une réinstallation depuis une image saine reste plus sûre qu’un nettoyage, surtout en présence de code en mémoire ou de droits élevés.' },
        ],
      },
      {
        name: 'Restauration',
        steps: [{ title: 'Remettre en service sous surveillance', detail: 'Levez l’isolement, gardez une surveillance renforcée sur l’hôte et le compte pendant au moins 7 jours.' }],
      },
      {
        name: 'Clôture',
        steps: [{ title: 'Rapport et règle', detail: 'Chronologie, IOC, TTP. Créez une règle ciblant le comportement, et pas seulement le hash.' }],
      },
    ],
    closure: ['Hash et C2 recherchés sur tout le parc', 'Persistance traitée', 'Identifiants renouvelés', 'Vecteur initial identifié et corrigé'],
    pitfalls: ['Lancer un antivirus et clôturer', 'Éteindre avant de capturer la mémoire', 'Se connecter en RDP avec un compte admin de domaine', 'Ne bloquer que le hash'],
  },
  {
    id: 'bruteforce',
    title: 'Brute-force et password spraying',
    severity: 'Moyenne',
    sla: 'Qualification sous 30 minutes',
    trigger: 'Nombreux 4625 ou échecs Entra ID, verrouillages en série',
    roles: 'N1 : qualification. N2 si un compte est compromis.',
    mitre: ['T1110.001', 'T1110.003', 'T1078'],
    phases: [
      {
        name: 'Identification',
        steps: [
          {
            title: 'Distinguer brute-force et spraying',
            detail: 'Brute-force : un compte, de nombreux mots de passe. Spraying : de nombreux comptes, un mot de passe, souvent lentement pour éviter le verrouillage.',
            code: {
              lang: 'kql',
              title: 'Vue par source',
              code: r`SigninLogs
| where TimeGenerated > ago(24h) and ResultType in ("50126", "50053")
| summarize Comptes = dcount(UserPrincipalName), Tentatives = count(), Apps = make_set(AppDisplayName, 5) by IPAddress
| order by Comptes desc`,
            },
          },
          {
            title: 'Chercher un succès : la question essentielle',
            detail: "Une attaque réussie change tout. Rapprochez les IP en échec des connexions réussies.",
            code: {
              lang: 'kql',
              title: 'Succès depuis les IP attaquantes',
              code: r`let Attaquants = SigninLogs
| where TimeGenerated > ago(24h) and ResultType == "50126"
| summarize Comptes = dcount(UserPrincipalName) by IPAddress
| where Comptes > 10
| project IPAddress;
SigninLogs
| where TimeGenerated > ago(24h) and ResultType == 0 and IPAddress in (Attaquants)
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName, ConditionalAccessStatus`,
            },
            decision: 'Au moins un succès ? Traitez ce compte selon le playbook de compromission M365 ou AD.',
          },
          {
            title: 'Écarter un faux positif',
            detail: 'Un seul compte, un seul hôte interne et des échecs réguliers : probablement un service, un téléphone ou une tâche planifiée avec un ancien mot de passe.',
            code: {
              lang: 'spl',
              title: 'Source des échecs',
              code: r`index=wineventlog EventCode=4625 Account_Name="svc-app"
| stats count by Source_Network_Address Workstation_Name Process_Name Sub_Status`,
            },
          },
        ],
      },
      {
        name: 'Confinement',
        steps: [
          { title: 'Bloquer la source', detail: 'Blocage de l’IP sur le pare-feu, WAF, VPN, ou localisation nommée en accès conditionnel. Attention : les attaquants changent souvent d’adresse.' },
          { title: 'Limiter l’exposition', detail: 'Bloquez l’authentification héritée (POP, IMAP, SMTP AUTH), restreignez VPN et RDP, vérifiez Smart Lockout.' },
          {
            title: 'Réinitialiser les comptes touchés',
            detail: 'Tout compte avec un succès depuis l’IP attaquante est compromis : révocation, reset, contrôle MFA.',
            code: {
              lang: 'powershell',
              title: 'Active Directory',
              code: r`Search-ADAccount -LockedOut | Select-Object SamAccountName,LastLogonDate
Set-ADAccountPassword -Identity j.martin -Reset
Set-ADUser -Identity j.martin -ChangePasswordAtLogon $true`,
            },
          },
        ],
      },
      {
        name: 'Éradication',
        steps: [{ title: 'Vérifier ce qui a suivi', detail: 'Après un succès : boîte aux lettres, nouvelles méthodes MFA, VPN, connexions RDP, mouvement latéral.' }],
      },
      {
        name: 'Clôture',
        steps: [{ title: 'Durcir', detail: 'MFA obligatoire, liste de mots de passe interdits (avec le nom de l’entreprise), alerte sur le nombre de comptes distincts par source.' }],
      },
    ],
    closure: ['Aucun succès non expliqué depuis les IP sources', 'Comptes concernés réinitialisés', 'Authentification héritée évaluée', 'Détection du spraying en place'],
    pitfalls: ['S’arrêter aux échecs sans chercher les succès', 'Compter par compte alors que le spraying se voit par source', 'Se fier au seul blocage d’IP', 'Oublier les codes `50126` et `50053` dans Entra'],
  },
  {
    id: 'ransomware',
    title: 'Ransomware et mouvement latéral (PsExec, SMB, RDP)',
    severity: 'Critique',
    sla: 'Mobilisation immédiate',
    trigger: 'Chiffrement massif, suppression de clichés, note de rançon, PsExec en chaîne',
    roles: 'Cellule de crise : direction, RSSI, IT, juridique, communication, assureur, prestataire PRIS.',
    mitre: ['T1021.002', 'T1570', 'T1490', 'T1486', 'T1003'],
    phases: [
      {
        name: 'Identification',
        steps: [
          {
            title: 'Déclarer la crise tout de suite',
            detail: 'N’attendez pas une certitude complète. Alertez le responsable d’astreinte et activez le canal hors bande.',
          },
          {
            title: 'Identifier la source et le compte',
            detail: 'D’où part le mouvement latéral ? Quel compte ?',
            code: {
              lang: 'kql',
              title: 'PsExec et services distants',
              code: r`SecurityEvent
| where TimeGenerated > ago(24h)
| where (EventID == 7045 and EventData has "PSEXESVC")
   or (EventID == 5145 and ShareName has "ADMIN$" and RelativeTargetName has_any (".exe", ".dll"))
   or (EventID == 4624 and LogonType == 3 and AuthenticationPackageName == "NTLM")
| summarize Hotes = dcount(Computer), Liste = make_set(Computer, 50) by Account, IpAddress
| order by Hotes desc`,
            },
          },
        ],
      },
      {
        name: 'Confinement',
        steps: [
          {
            title: 'Segmenter d’urgence',
            detail: 'Bloquez SMB (`445`), RDP (`3389`), WinRM (`5985`, `5986`) et RPC (`135`) entre les segments. Coupez les liens intersites et VPN si nécessaire.',
          },
          {
            title: 'Couper les comptes à privilèges exposés',
            detail: 'Désactivez le compte utilisé, ainsi que les comptes de service à forts privilèges. Gardez deux comptes de crise, stockés hors ligne. Attention au risque de panne : décision de la cellule de crise.',
            code: {
              lang: 'powershell',
              title: 'Active Directory',
              code: r`Disable-ADAccount -Identity svc-backup
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object SamAccountName
Get-SmbSession | Select-Object ClientComputerName,ClientUserName
Get-SmbOpenFile | Group-Object ClientUserName`,
            },
          },
          {
            title: 'Isoler sans éteindre',
            detail: 'Isolez les hôtes touchés. Gardez-les allumés : la mémoire peut contenir des clés et la preuve de la méthode d’accès. Hyperviseurs : prenez un snapshot avec mémoire si possible.',
          },
          {
            title: 'Protéger les sauvegardes',
            detail: 'Déconnectez ou verrouillez le dépôt, changez les identifiants du serveur de sauvegarde et vérifiez l’immutabilité. Les attaquants ciblent les sauvegardes en priorité.',
          },
          {
            title: 'Préserver les preuves',
            detail: 'Note de rançon, échantillon de fichier chiffré, binaire, mémoire d’au moins un hôte, journaux, en particulier s’ils sont locaux. Ne contactez pas l’attaquant sans décision de la cellule de crise.',
          },
        ],
      },
      {
        name: 'Éradication',
        steps: [
          {
            title: 'Établir le vecteur initial et les accès',
            detail: 'VPN, RDP exposé, phishing, CVE sur un service périphérique. Tant que le vecteur reste ouvert, toute restauration sera à refaire. Évaluez aussi l’exfiltration : la double extorsion est la norme.',
          },
          {
            title: 'Renouveler les secrets',
            detail: 'Tous les comptes à privilèges et de service. Double reset de `krbtgt`, espacé au moins de la durée de vie maximale des tickets (10 h par défaut) et après réplication.',
            code: {
              lang: 'powershell',
              title: 'Contrôle de la réplication',
              code: r`repadmin /replsummary
Get-ADUser krbtgt -Properties PasswordLastSet | Select-Object PasswordLastSet`,
            },
            decision: 'DCSync ou accès au DC confirmé ? Envisagez la reconstruction de la forêt avec un prestataire spécialisé.',
          },
        ],
      },
      {
        name: 'Restauration',
        steps: [
          { title: 'Restaurer par ordre de priorité', detail: 'Réseau et identité (AD), puis services critiques, puis métiers. Reconstruisez dans un environnement propre, et testez les sauvegardes avant de les connecter.' },
          { title: 'Surveillance renforcée', detail: 'EDR sur 100 % des machines restaurées avant réintégration, surveillance du C2, des comptes et des outils de l’attaquant.' },
        ],
      },
      {
        name: 'Clôture',
        steps: [
          { title: 'Obligations et notifications', detail: 'DPO et CNIL (72 h si données personnelles à risque), NIS 2 selon l’entité, assureur, dépôt de plainte. ANSSI / CERT-FR selon le contexte. Ces décisions relèvent de la cellule de crise.' },
          { title: 'RETEX', detail: 'Chronologie complète, causes racines, plan d’action daté : MFA sur les accès distants, tiering AD, segmentation, sauvegardes hors ligne testées.' },
        ],
      },
    ],
    closure: ['Vecteur initial fermé', 'Secrets et krbtgt renouvelés', 'Absence d’activité de l’attaquant confirmée', 'Exfiltration évaluée', 'Notifications réalisées', 'RETEX planifié'],
    pitfalls: ['Éteindre tous les serveurs d’un coup', 'Restaurer sur un réseau encore compromis', 'Utiliser un compte Domain Admin sur une machine infectée', 'Oublier les sauvegardes', 'Coordonner la crise sur un outil compromis'],
  },
  {
    id: 'dlp',
    title: 'Exfiltration de données et alerte DLP',
    severity: 'Haute',
    sla: 'Qualification sous 1 heure',
    trigger: 'Alerte DLP, volume sortant anormal, téléversement vers un service non approuvé',
    roles: 'N2 : investigation. DPO, juridique et RH si un salarié est concerné.',
    mitre: ['T1041', 'T1567.002', 'T1048', 'T1074'],
    phases: [
      {
        name: 'Identification',
        steps: [
          {
            title: 'Qualifier l’alerte DLP',
            detail: 'Quelle donnée (classification, client, RH), quel volume, quelle destination, quel canal ? Une correspondance sur un motif de numéro de carte peut être fausse : ouvrez un échantillon si vous en avez le droit.',
          },
          {
            title: 'Établir le volume et la chronologie',
            detail: 'Comparez aux habitudes de l’utilisateur sur 30 jours.',
            code: {
              lang: 'kql',
              title: 'Activité sortante',
              code: r`DeviceNetworkEvents
| where Timestamp > ago(7d) and DeviceName == "FIN-PC-042" and RemoteIPType == "Public"
| summarize Connexions = count(), Premier = min(Timestamp), Dernier = max(Timestamp) by RemoteUrl, InitiatingProcessFileName
| order by Connexions desc`,
            },
          },
          {
            title: 'Rechercher les outils et les archives',
            detail: '`rclone`, `MEGAsync`, `WinSCP`, `curl -T`, ou archives `7z` volumineuses créées juste avant (mise en attente, `T1074`).',
            code: {
              lang: 'kql',
              title: 'Outils d’exfiltration',
              code: r`DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("rclone.exe", "megacmd.exe", "winscp.exe", "pscp.exe") or ProcessCommandLine has_any ("rclone", "mega:", "transfer.sh", "-T ")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine`,
            },
          },
          {
            title: 'Trancher : externe, interne ou erreur',
            detail: 'Compte compromis, salarié malveillant ou maladresse (copie vers un OneDrive personnel) ?',
            decision: "Suspicion sur un salarié : limitez la diffusion, impliquez immédiatement RH et juridique. Les vérifications doivent rester proportionnées et conformes au cadre légal et interne.",
          },
        ],
      },
      {
        name: 'Confinement',
        steps: [
          { title: 'Couper le canal', detail: 'Blocage du domaine ou du service, révocation de la session cloud ou du lien de partage, isolement de l’hôte si un compte a été compromis.' },
          { title: 'Préserver les preuves', detail: 'Journaux de proxy, de DLP et de cloud, à conserver avant rotation. Copie forensique en cas d’action judiciaire possible.' },
          { title: 'Demander le retrait', detail: 'Le juridique peut demander la suppression auprès du fournisseur de stockage, si la destination le permet.' },
        ],
      },
      {
        name: 'Éradication',
        steps: [
          {
            title: 'Traiter la cause',
            detail: 'Compte compromis : playbook M365 ou malware. Partage trop ouvert : corrigez les droits. Liens anonymes : désactivez-les.',
            code: {
              lang: 'kql',
              title: 'Téléchargements massifs SharePoint et OneDrive',
              code: r`OfficeActivity
| where TimeGenerated > ago(7d) and Operation in ("FileDownloaded", "FileSyncDownloadedFull")
| summarize Fichiers = count(), Sites = dcount(Site_Url) by UserId, ClientIP
| where Fichiers > 500
| order by Fichiers desc`,
            },
          },
        ],
      },
      {
        name: 'Clôture',
        steps: [
          { title: 'Évaluer l’impact sur les données', detail: 'Liste des données exposées, nombre de personnes concernées, sensibilité. Le DPO évalue l’obligation de notification (72 h).' },
          { title: 'Améliorer les contrôles', detail: 'Politiques DLP ajustées, blocage des services non approuvés (CASB), classification, alerte sur `rclone`.' },
        ],
      },
    ],
    closure: ['Volume et données exposées établis', 'Canal coupé', 'Cause traitée', 'Décision DPO et juridique documentée'],
    pitfalls: ['Accuser un salarié avant d’avoir écarté le compte compromis', 'Laisser expirer les logs', 'Mener seul une enquête sur un salarié', 'Ignorer un volume modeste de données très sensibles'],
  },
]
