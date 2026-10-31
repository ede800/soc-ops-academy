import type { Module } from '../../types'
import { code, danger, h, info, links, ol, p, r, table, tip, warn } from '../blocks'

export const m6: Module = {
  id: 'playbooks',
  number: 6,
  title: 'Playbooks de réponse à incident, SOAR et remédiation',
  tier: 'N2',
  summary:
    "Comment structurer une réponse, quoi automatiser sans risque, comment préserver les preuves et comment communiquer pendant la crise. Les 5 playbooks complets sont dans la bibliothèque.",
  objectives: [
    'Comprendre la structure d’un playbook opérationnel',
    'Choisir le bon niveau d’automatisation SOAR',
    'Contenir sans détruire les preuves',
    'Coordonner remédiation et communication',
  ],
  sections: [
    {
      id: 'structure',
      title: 'Anatomie d’un playbook',
      blocks: [
        p("Un playbook n'est pas un cours : c'est une liste d'actions exécutable à 3 h du matin par quelqu'un de fatigué. Chaque étape doit dire quoi faire, avec quel outil, et comment savoir que c'est fait."),
        table(
          ['Élément', 'Contenu', 'Exemple'],
          ['Déclencheur', 'Quelle alerte l’active ?', 'Alerte EDR « Credential dumping »'],
          ['Rôles', 'Qui décide, qui exécute ?', 'N2 exécute, responsable SOC valide l’isolement d’un serveur'],
          ['Décisions', 'Points de branchement explicites', 'Compte à privilèges ? Oui : escalade immédiate'],
          ['Actions', 'Commandes exactes', '`Revoke-MgUserSignInSession`'],
          ['Critères de sortie', 'Quand passer à la suite ?', 'Aucun nouveau signe de C2 depuis 24 h'],
          ['Preuves', 'Quoi conserver et où ?', 'Image mémoire, logs exportés, chaîne de garde'],
        ),
        info('Bibliothèque', 'Les 5 playbooks détaillés sont disponibles dans l’onglet Playbooks, sous forme de listes de contrôle interactives dont la progression est sauvegardée.'),
      ],
    },
    {
      id: 'soar',
      title: 'SOAR : quoi automatiser ?',
      blocks: [
        table(
          ['Action', 'Automatiser ?', 'Raison'],
          ['Enrichissement (hash, IP, utilisateur)', 'Oui, toujours', 'Aucun risque, gain de temps immédiat'],
          ['Création de ticket, notification', 'Oui', 'Sans impact métier'],
          ['Purge d’un mail avéré malveillant', 'Oui, avec seuil de confiance', 'Facilement réversible'],
          ['Isolement d’un poste utilisateur', 'Oui si détection de haute confiance', 'Réversible, impact limité'],
          ['Désactivation d’un compte standard', 'Validation humaine rapide', 'Impact possible sur un service'],
          ['Isolement d’un serveur critique', 'Validation humaine obligatoire', 'Impact métier important'],
          ['Action sur un compte à privilèges ou un DC', 'Jamais sans validation', 'Risque de panne générale'],
        ),
        danger('Une erreur à vitesse machine', "Une règle SOAR qui isole automatiquement « tout hôte avec PsExec » peut couper tous les serveurs lors d'une opération de maintenance. Prévoyez des listes d'exclusion (DC, hyperviseurs), des plafonds (maximum N isolements par heure) et un bouton d'arrêt."),
        code('text', 'Exemple de logique SOAR', r`
ALERTE : phishing signalé par un utilisateur
  1. Extraire expéditeur, URLs, hash            [auto]
  2. Enrichir (TIP, réputation, âge du domaine) [auto]
  3. Chercher les destinataires dans le tenant  [auto]
  4. Score >= 80 ?
       Oui -> Purger + bloquer l'expéditeur     [auto]
       Non -> Tâche pour N1                     [humain]
  5. Clic détecté ?
       Oui -> Vérifier SigninLogs et escalader  [humain]
  6. Répondre à l'utilisateur                   [auto]
`),
      ],
    },
    {
      id: 'preuves',
      title: 'Contenir sans détruire les preuves',
      blocks: [
        h('Ordre de volatilité (RFC 3227)'),
        ol(
          'Registres et cache du processeur',
          'Mémoire vive : processus, connexions, clés de chiffrement',
          'État du réseau, connexions actives',
          'Disque',
          'Journaux distants et sauvegardes',
        ),
        danger('Ne pas éteindre ni redémarrer', "Éteindre une machine efface la mémoire : processus injectés, connexions, parfois clés de chiffrement d'un ransomware. **Isolez sur le réseau** et gardez la machine allumée, sauf consigne contraire de la cellule de crise."),
        table(
          ['Besoin', 'Outil', 'Commande'],
          ['Mémoire', 'WinPmem, Magnet RAM Capture', '`winpmem_mini_x64.exe mem.raw`'],
          ['Triage disque', 'KAPE', '`kape.exe --tsource C: --tdest D:\\triage --target !SANS_Triage --vhdx %m`'],
          ['Collecte à grande échelle', 'Velociraptor', 'Artefact `Windows.KapeFiles.Targets`'],
          ['Isolement', 'EDR', 'Action « Isolate device » : garde la communication avec la console'],
          ['Empreinte', 'PowerShell', '`Get-FileHash fichier -Algorithm SHA256`'],
        ),
        warn('Chaîne de garde', "Si une action judiciaire est possible, consignez qui a collecté quoi, quand, avec quel outil, et le hash obtenu. Travaillez sur des copies. En France, conservez les preuves avant toute remise en état et rapprochez-vous de votre juridique pour un éventuel dépôt de plainte."),
        tip('Ne restez pas connecté à une machine compromise avec un compte à privilèges', "Une session interactive laisse des identifiants en mémoire, que l'attaquant peut voler avec Mimikatz. Préférez les actions à distance de l'EDR, ou un compte dédié à la réponse à incident, sans privilège hors de ce périmètre."),
      ],
    },
    {
      id: 'coordination',
      title: 'Coordination, communication, obligations',
      blocks: [
        table(
          ['Principe', 'Détail'],
          ['Remédiation coordonnée', 'Traitez tous les comptes et hôtes au même moment, pour ne pas laisser à l’attaquant le temps de réagir'],
          ['Canal séparé', "Si l'AD ou M365 est compromis, l'attaquant peut lire Teams et les mails. Prévoyez un canal hors bande"],
          ['Journal de bord', 'Tout horodater en UTC : qui, quoi, quand, résultat'],
          ['Un seul porte-parole', 'Évite les messages contradictoires'],
          ['Pas de spéculation', 'Distinguez ce qui est observé de ce qui est supposé'],
        ),
        h('Obligations à connaître en France et en Europe'),
        table(
          ['Texte', 'Obligation', 'Délai'],
          ['RGPD, art. 33', 'Notifier à la CNIL une violation de données personnelles présentant un risque', '72 heures après en avoir pris connaissance'],
          ['RGPD, art. 34', 'Informer les personnes concernées en cas de risque élevé', 'Dans les meilleurs délais'],
          ['NIS 2', 'Entités concernées : alerte précoce, notification, rapport final', '24 h, 72 h, 1 mois'],
          ['Cyber-assurance', 'Déclaration selon le contrat', 'Vérifiez avant la crise'],
        ),
        info('À vérifier', "Le SOC ne décide pas seul de ces notifications : elles relèvent du DPO, du juridique et de la direction. Votre rôle est de leur fournir rapidement des faits fiables. L'ANSSI et le CERT-FR restent des points de contact à prévoir dans le plan de crise, et la transposition de NIS 2 peut différer selon les pays."),
        code('text', 'Point de situation de crise (toutes les 2 à 4 h)', r`
Heure (UTC)     : 14:00
Situation       : Chiffrement arrêté. 12 serveurs impactés, 3 contenus.
Ce qui est sûr  : Accès initial VPN via compte svc-vpn. PsExec depuis SRV-APP02.
Ce qui est incertain : Exfiltration (analyse du proxy en cours).
Actions en cours: Rotation krbtgt (1re), restauration AD hors ligne.
Décisions requises : Coupure du site B jusqu'à 18:00 UTC ?
Prochain point  : 18:00 UTC
`),
      ],
    },
    {
      id: 'cinq-playbooks',
      title: 'Les 5 playbooks en un coup d’œil',
      blocks: [
        p('Chaque playbook suit la même progression : identification, confinement, éradication, puis clôture. Ce tableau donne le réflexe clé ; le détail, les commandes et les points de décision sont dans la bibliothèque.'),
        table(
          ['Playbook', 'Déclencheur type', 'Actions à ne pas oublier'],
          ['Phishing, compromission M365 (AiTM, vol de jeton)', 'Connexion anormale après un clic, MFA déjà satisfaite', 'Révoquer les sessions, réinitialiser la MFA, contrôler les règles de boîte cachées (Inbox Rules)'],
          ['Malware, alerte EDR sur un poste', 'Détection EDR ou lignée de processus anormale', 'Isoler le poste via l’EDR, collecter la mémoire et le triage (KAPE, Velociraptor), bloquer le hash SHA-256'],
          ['Brute force, password spraying', 'Rafale de `4625` ou d’échecs Entra ID', 'Chercher le succès après les échecs, bloquer la source, réinitialiser les comptes touchés, renforcer la MFA'],
          ['Ransomware, mouvement latéral (PsExec, SMB, RDP)', '`7045` PSEXESVC, suppression des clichés, renommage massif', 'Confinement d’urgence, couper les comptes à privilèges, garder les machines allumées, préserver les preuves'],
          ['Exfiltration de données, alerte DLP', 'Volume sortant anormal ou alerte DLP', 'Qualifier les données, bloquer le canal, conserver les preuves, impliquer le DPO et le juridique'],
        ),
        links(
          { to: '/playbooks/m365-aitm', label: 'Phishing et compromission M365' },
          { to: '/playbooks/malware-edr', label: 'Malware et alerte EDR' },
          { to: '/playbooks/bruteforce', label: 'Brute force et spraying' },
          { to: '/playbooks/ransomware', label: 'Ransomware et mouvement latéral' },
          { to: '/playbooks/dlp', label: 'Exfiltration et DLP' },
        ),
        warn('Le piège des faux positifs', "Un test d’intrusion, un script d’administration ou un outil de sauvegarde produisent les mêmes signaux qu’une attaque : `PsExec`, volume sortant, rafale de `4625` après un changement de mot de passe. Avant une action à fort impact, vérifiez le calendrier des tests et les changements en cours, puis confirmez avec le propriétaire du compte par un second canal. Ne laissez pas ce contrôle retarder le confinement si le chiffrement ou l'exfiltration est en cours."),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['Situation', 'Première action'],
      ['Compte M365 compromis', '`Revoke-MgUserSignInSession`, reset, contrôle des Inbox Rules'],
      ['Malware sur un poste', 'Isolement EDR, mémoire, blocage du SHA-256'],
      ['Brute-force / spraying', 'Blocage de l’IP, recherche de succès, reset'],
      ['Ransomware', 'Segmentation, comptes à privilèges coupés, preuves'],
      ['Exfiltration / DLP', 'Qualifier avec le juridique, couper le canal, préserver'],
    ),
    code('powershell', 'Commandes M365 et AD essentielles', r`
# Révoquer les sessions
Revoke-MgUserSignInSession -UserId user@contoso.example

# Règles de boîte, y compris cachées
Get-InboxRule -Mailbox user@contoso.example -IncludeHidden

# Transfert au niveau de la boîte
Get-Mailbox user@contoso.example | Select-Object ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward

# Désactiver un compte AD
Disable-ADAccount -Identity j.martin

# Comptes à privilèges
Get-ADGroupMember "Domain Admins" -Recursive | Select-Object Name,SamAccountName
`),
  ],
  quiz: [
    {
      q: 'Un poste exécute un ransomware. Quelle est la première action sur cette machine ?',
      options: ['L’éteindre', 'L’isoler du réseau et la laisser allumée', 'Lancer un antivirus complet', 'La réinstaller'],
      answer: 1,
      explain: "Isoler arrête la propagation. Garder la machine allumée préserve la mémoire, qui peut contenir des preuves et parfois des clés.",
    },
    {
      q: 'Quelle action SOAR peut être automatisée sans validation humaine ?',
      options: ['Isoler un contrôleur de domaine', 'Réinitialiser un administrateur de domaine', 'Enrichir un hash dans le TIP', 'Couper un site réseau'],
      answer: 2,
      explain: "L'enrichissement est sans risque. Les actions à fort impact métier exigent une validation humaine et des garde-fous.",
    },
    {
      q: 'Quel est le délai de notification à la CNIL pour une violation de données à risque ?',
      options: ['24 heures', '72 heures', '7 jours', '30 jours'],
      answer: 1,
      explain: "L'article 33 du RGPD prévoit 72 heures après en avoir pris connaissance. La décision revient au DPO et à la direction, à partir des faits fournis par le SOC.",
    },
    {
      q: 'Pourquoi faut-il éviter de se connecter en RDP à un poste compromis avec un compte de domaine à privilèges ?',
      options: [
        'Le RDP est lent',
        'Les identifiants restent en mémoire et l’attaquant peut les voler',
        'Le RDP efface les journaux',
        'Cela désactive l’EDR du poste pendant toute la session et empêche ensuite la collecte de la mémoire',
      ],
      answer: 1,
      explain: 'Une session interactive expose les identifiants à un dump de LSASS. Utilisez les actions à distance ou un compte dédié à faible portée.',
    },
    {
      q: 'Pourquoi coordonner la remédiation plutôt que nettoyer hôte par hôte ?',
      options: [
        'Pour réduire les coûts de licence',
        "Pour éviter que l'attaquant, alerté, change de méthode via ses autres accès",
        'Parce que l’EDR ne gère qu’un seul hôte à la fois, ce qui impose d’attendre la fin de chaque isolement',
        'Pour obtenir de meilleurs KPI',
      ],
      answer: 1,
      explain: "Si vous coupez un seul accès, l'attaquant s'en aperçoit et peut réagir avec ceux qui restent, ou accélérer le chiffrement.",
    },
    {
      q: 'Quelle source de preuve est la plus volatile ?',
      options: ['Les sauvegardes', 'Les logs dans le SIEM', 'La mémoire vive', 'Le disque'],
      answer: 2,
      explain: "La RAM disparaît à l'extinction. C'est pourquoi on la capture avant le disque.",
    },
    {
      q: 'Pendant une crise impliquant la compromission de M365, où coordonner l’équipe ?',
      options: ['Dans Teams, comme d’habitude', 'Sur un canal hors bande, indépendant du SI', 'Par mail d’entreprise', 'Dans le chat de la console EDR uniquement'],
      answer: 1,
      explain: "L'attaquant peut lire vos échanges s'il a accès au tenant. Prévoyez ce canal et sa liste de contacts avant la crise.",
    },
  ],
}
