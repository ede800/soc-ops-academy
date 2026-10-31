import type { Module } from '../../types'
import { code, danger, h, info, ol, p, r, table, tip, ul, warn } from '../blocks'

export const m1: Module = {
  id: 'fondamentaux',
  number: 1,
  title: "Fondamentaux SOC, triage et cycle de vie d'un incident",
  tier: 'N1',
  summary:
    "L'architecture d'un SOC moderne, le rôle de chaque niveau, les frameworks qui structurent l'investigation et la méthode pour qualifier une alerte sans se tromper.",
  objectives: [
    'Situer SIEM, EDR/XDR, SOAR, NDR et TIP dans la chaîne de détection',
    'Savoir ce qui relève du N1, du N2 et du N3, et quand escalader',
    'Relier une observation à la Kill Chain, à ATT&CK et à une phase PICERL',
    'Distinguer TP, FP et B-TP avec une méthode reproductible',
  ],
  sections: [
    {
      id: 'architecture',
      title: "Architecture d'un SOC moderne",
      blocks: [
        p("Un SOC transforme de la télémétrie brute en décisions. Chaque brique répond à une question précise, et aucune ne suffit seule : l'EDR voit le processus mais pas le flux entre deux VLAN, le NDR voit le flux mais pas la ligne de commande."),
        table(
          ['Brique', 'Question à laquelle elle répond', 'Exemples', 'Angle mort typique'],
          ['SIEM', "Que s'est-il passé, partout, et peut-on le corréler ?", 'Splunk, Microsoft Sentinel, QRadar, Elastic', "Ne voit que ce qu'on lui envoie ; coût d'ingestion, donc journaux souvent manquants"],
          ['EDR / XDR', "Que fait ce processus sur ce poste, et peut-on l'arrêter ?", 'Defender for Endpoint, CrowdStrike, SentinelOne', 'Serveurs sans agent, équipements réseau, appliances, Linux embarqué'],
          ['NDR', 'Que circule-t-il sur le réseau, y compris entre machines internes ?', 'Zeek, Suricata, Corelight, Vectra', 'Trafic chiffré (TLS) : métadonnées seulement ; hôtes hors des points de capture'],
          ['SOAR', 'Comment exécuter la réponse sans erreur et à vitesse machine ?', 'Sentinel Playbooks, Cortex XSOAR, Tines', 'Automatise aussi les erreurs : une mauvaise règle peut isoler un contrôleur de domaine'],
          ['TIP (Threat Intelligence Platform)', 'Cet indicateur est-il connu ? Par qui est-il utilisé ?', 'MISP, OpenCTI, ThreatConnect', 'Les IOC vieillissent vite ; IP partagées, CDN et faux positifs'],
        ),
        code('text', 'Le parcours d’une alerte', r`
Sources        Postes (EDR, Sysmon) | AD | M365 | Proxy | Pare-feu | DNS | Cloud
   |
Collecte       Agents, Syslog, API, normalisation (ASIM, CIM, ECS)
   |
Détection      Règles SIEM / Sigma, analytique EDR, enrichissement TIP
   |
File d'alertes N1 : qualification TP / FP / B-TP en quelques minutes
   |
Incident       N2 : périmètre, confinement, éradication, avec SOAR
   |
Retour         N3 : nouvelles règles, chasses, correction des angles morts
`),
        warn('Ne jamais confondre absence de log et absence d’attaque', "« Rien dans le SIEM » signifie seulement « rien dans ce qui a été collecté ». Avant de conclure, vérifiez que la source remontait bien à cette heure-là. Une source muette est un signal en soi, surtout si le journal a été effacé (`1102`)."),
      ],
    },
    {
      id: 'roles',
      title: 'Rôles N1, N2 et N3',
      blocks: [
        table(
          ['Niveau', 'Mission', 'Livrable', 'Escalade quand…'],
          ['N1 - Triage', 'Qualifier vite, enrichir, documenter', 'Ticket qualifié avec preuves', "Compte à privilèges, signe de mouvement latéral, doute après 15 à 20 minutes, ou périmètre supérieur à un hôte"],
          ['N2 - Investigation', 'Établir le périmètre, contenir, éradiquer', 'Chronologie, IOC, rapport', "Compromission de l'AD, exfiltration confirmée, technique inconnue, impact métier"],
          ['N3 - Threat Hunting et règles de détection', 'Chercher ce qui n’a pas alerté, créer les règles', 'Règles testées, hypothèses, couverture ATT&CK', "Crise majeure : le N3 rejoint alors la cellule d'incident"],
        ),
        tip('Une bonne escalade tient en quatre phrases', "Ce que j'ai observé, ce que j'ai vérifié, ce que j'en déduis, ce que je demande. « Alerte bizarre sur PC-042 » fait perdre du temps ; « `WINWORD.EXE` a lancé un PowerShell encodé sur PC-042 à 09:14 UTC, connexion vers une IP inconnue confirmée, je demande l'isolement » permet d'agir."),
        h('Indicateurs de pilotage'),
        table(
          ['KPI', 'Définition', 'Piège'],
          ['MTTD', "Temps moyen entre le début de l'activité et sa détection", "Le début réel n'est connu qu'après l'enquête"],
          ['MTTA', "Temps moyen entre l'alerte et sa prise en charge", 'Se dégrade vite en cas de fatigue aux alertes'],
          ['MTTR', "Temps moyen jusqu'à la résolution ou au confinement", "Clôturer vite n'est pas contenir : définissez ce que vous mesurez"],
          ['Taux de FP par règle', 'Part des alertes fausses, règle par règle', 'Une moyenne globale masque les règles les plus bruyantes'],
        ),
      ],
    },
    {
      id: 'frameworks',
      title: 'Kill Chain, ATT&CK, NIST et PICERL',
      blocks: [
        p("Ces cadres ne se concurrencent pas. La Kill Chain raconte la progression de l'attaque, ATT&CK nomme précisément les comportements, NIST et PICERL organisent votre réponse."),
        h('Cyber Kill Chain (Lockheed Martin)'),
        table(
          ['Étape', 'Côté attaquant', 'Trace côté SOC'],
          ['1. Reconnaissance', 'OSINT, scan externe', 'Logs de pare-feu, WAF (souvent invisible)'],
          ['2. Weaponization', 'Création de la charge', 'Invisible : se déroule chez l’attaquant'],
          ['3. Delivery', 'Email, lien, service exposé', 'Passerelle mail, proxy, WAF'],
          ['4. Exploitation', 'Macro, CVE', 'Sysmon 1, crash applicatif, EDR'],
          ['5. Installation', 'Persistance', 'Sysmon 11/13, `4698`, `7045`'],
          ['6. C2', 'Canal de contrôle', 'Proxy, DNS, Zeek, Sysmon 3'],
          ['7. Actions sur objectifs', 'Vol, chiffrement', 'DLP, partage SMB, EDR'],
        ),
        info('Limite de la Kill Chain', "Elle est linéaire et centrée sur le périmètre. Un attaquant qui se connecte avec un compte valide saute plusieurs étapes. C'est pourquoi on la complète par ATT&CK, qui décrit des comportements indépendants d'un ordre strict."),
        h('MITRE ATT&CK : tactique, technique, procédure'),
        ul(
          "**Tactique** : le pourquoi (`TA0006` Credential Access).",
          "**Technique** : le comment (`T1558.003` Kerberoasting).",
          "**Procédure** : la mise en œuvre réelle (`Rubeus.exe kerberoast /rc4opsec`).",
        ),
        p("Une même technique peut servir plusieurs tactiques : un compte valide (`T1078`) relève à la fois de l'accès initial, de la persistance, de l'élévation de privilèges et de l'évasion. Choisissez la tactique qui décrit le mieux l'objectif observé à cet instant."),
        h('NIST SP 800-61 et SANS PICERL'),
        table(
          ['NIST SP 800-61 (r2)', 'SANS PICERL', 'Question clé', 'Exemple concret'],
          ['Préparation', 'Préparation', 'Sommes-nous prêts ?', 'Playbooks, journalisation, comptes de crise, contacts'],
          ['Détection et analyse', 'Identification', 'Est-ce un incident ? Quelle portée ?', 'Qualification, chronologie, recherche d’IOC'],
          ['Confinement, éradication, restauration', 'Confinement', "Comment arrêter l'hémorragie ?", 'Isoler, désactiver un compte, bloquer un domaine'],
          ['', 'Éradication', 'Comment retirer la menace ?', 'Supprimer la persistance, réinitialiser les secrets'],
          ['', 'Restauration', 'Comment revenir sans risque ?', 'Réinstaller, restaurer, surveiller renforcée'],
          ['Activité post-incident', 'Leçons apprises', "Qu'est-ce qui change ?", 'Nouvelles règles, durcissement, RETEX sous 2 semaines'],
        ),
        info('Évolution du NIST', "La révision 3 de SP 800-61, publiée en avril 2025, réaligne la réponse à incident sur les fonctions du CSF 2.0 (Govern, Identify, Protect, Detect, Respond, Recover). Le cycle en quatre phases de la révision 2 reste la référence la plus citée en SOC et en entretien : connaissez les deux."),
        warn("L'ordre compte", "Éradiquer avant d'avoir établi le périmètre prévient l'attaquant et laisse ses autres points d'accès actifs. Coordonnez la remédiation : tous les comptes et hôtes concernés en même temps."),
      ],
    },
    {
      id: 'triage',
      title: 'Méthodologie de triage : TP, FP et B-TP',
      blocks: [
        table(
          ['Verdict', 'Définition', 'Exemple', 'Action'],
          ['Vrai positif (TP)', 'Le comportement détecté a eu lieu et il est malveillant', 'Macro Word qui lance PowerShell encodé', 'Escalade et confinement'],
          ['Faux positif (FP)', "La règle s'est trompée : le comportement visé n'a pas eu lieu", 'Une règle `*-enc*` qui se déclenche sur `-Encoding UTF8`', 'Clôture et correction de la règle'],
          ['Vrai positif bénin (B-TP)', 'Le comportement a bien eu lieu mais il est autorisé', "Kerberoasting lors d'un test d'intrusion planifié, ajout d'un admin avec ticket de changement", 'Clôture, avec preuve de l’autorisation'],
        ),
        danger('La confusion la plus coûteuse', "« C'est sûrement l'admin » n'est pas une preuve. Un B-TP exige une autorisation vérifiable : ticket, périmètre, horaire, confirmation par un canal distinct. Un attaquant utilise précisément les outils et comptes des administrateurs."),
        h('La méthode en 6 questions'),
        ol(
          "**Que dit la règle ?** Lisez sa logique : qu'est-ce qui l'a fait se déclencher exactement ?",
          "**Le déclencheur est-il réel ?** Retrouvez le log brut. S'il ne correspond pas au comportement visé, c'est un FP.",
          "**Qui et où ?** Criticité du compte et de l'hôte : un compte de service sur un DC ne se traite pas comme un poste de stagiaire.",
          "**Est-ce habituel ?** Cherchez 30 jours en arrière : ce compte fait-il ceci, depuis cette machine, à cette heure ?",
          "**Y a-t-il une autorisation ?** Ticket de changement, calendrier de pentest, confirmation directe.",
          "**Que s'est-il passé juste avant et juste après ?** Élargissez à ±30 minutes sur le même hôte et le même compte.",
        ),
        h("Pyramid of Pain : quelle preuve a de la valeur ?"),
        table(
          ['Niveau', 'Exemple', "Coût de contournement pour l'attaquant"],
          ['Hash', 'SHA-256 du binaire', 'Trivial : recompiler'],
          ['IP', 'Serveur C2', 'Facile : changer de VPS'],
          ['Domaine', 'Domaine du C2', 'Simple : quelques euros'],
          ['Artefacts réseau et hôte', 'User-Agent, nom de canal nommé', 'Agaçant'],
          ['Outils', 'Mimikatz, Cobalt Strike', 'Difficile'],
          ['TTP', 'Dump de LSASS, Kerberoasting', 'Très difficile : changer de méthode'],
        ),
        tip('Mauvaise réputation ≠ malveillant, bonne réputation ≠ sain', "Un domaine vierge sur VirusTotal n'innocente rien : les charges ciblées n'y figurent pas. À l'inverse, une IP Cloudflare signalée « malveillante » héberge des milliers de sites légitimes. La réputation est un indice, pas un verdict."),
        code('text', 'Modèle de note de clôture', r`
Qui      : j.martin (Finance), poste FIN-PC-042
Quoi     : WINWORD.EXE a lancé cmd.exe puis powershell.exe -nop -w hidden -enc
Quand    : 2026-03-12 09:14:22 UTC
Où       : FIN-PC-042 (10.20.4.42) vers 203.0.113.50:443
Pourquoi : lignée anormale, charge décodée = téléchargement en mémoire, IP inconnue
Verdict  : TP. Hôte isolé, escalade N2, hash bloqué. Ticket INC-20418
`),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['À retenir', 'Réflexe'],
      ['TP', 'Le comportement est réel et malveillant : confiner, escalader'],
      ['FP', 'Le comportement n’a pas eu lieu : clôturer, corriger la règle'],
      ['B-TP', 'Réel mais autorisé : clôturer avec la preuve, envisager une exclusion ciblée'],
      ['PICERL', 'Préparation, Identification, Confinement, Éradication, Restauration, Leçons'],
      ['Horodatage', 'Toujours en UTC, avec le fuseau explicite'],
      ['Défanger', 'Toujours : `hxxps[://]exemple[.]com` dans les tickets et les chats'],
      ['TLP', '`CLEAR`, `GREEN`, `AMBER`, `AMBER+STRICT`, `RED`'],
    ),
    code('text', 'Les 5 réflexes du triage', r`
1. Lire la logique de la règle avant de lire l'alerte
2. Retrouver le log brut : ne jamais conclure sur le titre
3. Élargir de ±30 min sur le même hôte et le même compte
4. Comparer à 30 jours d'historique
5. Écrire la note de clôture comme si un auditeur la relisait
`),
  ],
  quiz: [
    {
      q: "Une règle `*mimikatz*` se déclenche sur `C:\\Temp\\rapport-detection-mimikatz.docx` ouvert par un analyste. Aucun processus Mimikatz n'a été lancé. Quel est le verdict ?",
      options: ['Vrai positif', 'Faux positif', 'Vrai positif bénin', 'Incident à escalader'],
      answer: 1,
      explain: "Le comportement visé (l'exécution de Mimikatz) n'a jamais eu lieu : la règle a simplement trouvé la chaîne dans un nom de fichier. C'est un FP, à corriger en ciblant l'image du processus plutôt qu'une chaîne libre.",
    },
    {
      q: "L'équipe Red Team lance un Kerberoasting prévu au calendrier, confirmé par le responsable sécurité. L'alerte se déclenche. Verdict ?",
      options: ['Faux positif : ce n’est pas une attaque', 'Vrai positif bénin', 'Vrai positif : escalade et isolation', 'Sans objet'],
      answer: 1,
      explain: "La détection est juste : le comportement a bien eu lieu. Il est simplement autorisé et vérifié, donc B-TP. Le classer en FP ferait croire à tort que la règle est mauvaise.",
    },
    {
      q: "Quelle phase PICERL correspond à l'isolement réseau d'un poste via l'EDR ?",
      options: ['Identification', 'Confinement', 'Éradication', 'Restauration'],
      answer: 1,
      explain: "Isoler arrête la propagation sans retirer la menace. L'éradication viendra ensuite (suppression de la persistance, réinstallation).",
    },
    {
      q: "Dans la Pyramid of Pain, quel élément coûte le plus à l'attaquant s'il est détecté ?",
      options: ['Le hash du binaire', "L'IP du C2", 'Le nom de domaine', 'Le comportement (TTP)'],
      answer: 3,
      explain: "Changer de hash, d'IP ou de domaine est rapide. Changer de méthode oblige à revoir ses outils et son savoir-faire : c'est pourquoi les détections comportementales durent plus longtemps.",
    },
    {
      q: "Vous découvrez un compte compromis. Pourquoi ne pas le désactiver immédiatement si l'enquête N2 a déjà commencé à cartographier d'autres accès ?",
      options: [
        "Il ne faut jamais désactiver de compte",
        "Agir seul peut alerter l'attaquant, qui conserve ses autres accès : la remédiation doit être coordonnée",
        "La désactivation d’un compte efface ses journaux d’authentification et détruit toutes les preuves utiles à l’enquête",
        'Seul le N3 peut désactiver un compte',
      ],
      answer: 1,
      explain: "Une action isolée peut déclencher une réaction de l'attaquant (changement de canal, chiffrement anticipé). En cas de risque actif grave, on contient sans attendre ; sinon on coordonne avec le N2.",
    },
    {
      q: 'VirusTotal affiche 0/70 pour un domaine contacté par un PowerShell caché, enregistré il y a trois jours. Que conclure ?',
      evidence: { lang: 'log', code: 'Image=powershell.exe ParentImage=winword.exe DestinationHostname=cdn-sync-update.example VT=0/70 DomainAge=3j' },
      options: [
        'Sain, car aucun moteur ne le détecte',
        'Faux positif de la règle : un domaine absent de toutes les bases de réputation est forcément un domaine sain',
        'Suspect : un score nul ne prouve rien, la lignée et l’âge du domaine priment',
        'Bloquer tout VirusTotal',
      ],
      answer: 2,
      explain: "Une infrastructure récente et ciblée n'est pas encore référencée. Le contexte comportemental (Word qui lance PowerShell) est bien plus parlant que la réputation.",
    },
    {
      q: 'Quelle information manque dans cette note de clôture : « PowerShell suspect sur PC-12, fermé » ?',
      options: ['Uniquement la date', 'Uniquement le compte', 'Presque tout : preuves, chronologie, raisonnement et actions', 'Rien : une note courte suffit dès lors que le verdict et le nom de la règle déclenchée sont indiqués'],
      answer: 2,
      explain: "Une note doit permettre à un tiers de refaire le raisonnement : qui, quoi, quand, où, pourquoi, verdict et actions menées.",
    },
  ],
}
