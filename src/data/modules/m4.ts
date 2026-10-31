import type { Module } from '../../types'
import { code, danger, h, info, ol, p, r, table, tip, ul, warn } from '../blocks'

export const m4: Module = {
  id: 'phishing',
  number: 4,
  title: "Phishing et analyse d'emails",
  tier: 'N1-N2',
  summary:
    "Le vecteur initial le plus courant : lire un en-tête, interpréter SPF, DKIM et DMARC, puis analyser URLs et pièces jointes sans compromettre l'OPSEC.",
  objectives: [
    'Lire les en-têtes `Received` dans le bon sens pour retrouver la source',
    'Interpréter SPF, DKIM et DMARC, y compris l’alignement',
    'Analyser `.iso`, `.lnk`, `.hta`, macros et PDF sans les exécuter',
    'Utiliser CyberChef, VirusTotal, URLScan et Any.Run en respectant le TLP',
  ],
  sections: [
    {
      id: 'headers',
      title: "Lire un en-tête d'email",
      blocks: [
        table(
          ['Champ', 'Rôle', 'Fiabilité', 'Ce qu’il faut vérifier'],
          ['`From`', 'Expéditeur affiché', 'Falsifiable', 'Domaine réel, sosie, nom affiché trompeur'],
          ['`Return-Path`', 'Adresse de rebond (enveloppe)', 'Définie par l’expéditeur', 'Domaine utilisé par SPF'],
          ['`Reply-To`', 'Destination des réponses', 'Falsifiable', 'Différent du `From` : classique dans les fraudes au virement'],
          ['`Received`', 'Trace de chaque relais', 'Seuls ceux ajoutés par vos serveurs sont sûrs', 'Se lit **de bas en haut**'],
          ['`Message-ID`', 'Identifiant unique', 'Falsifiable', 'Domaine cohérent avec l’expéditeur'],
          ['`Authentication-Results`', 'Verdict de vos serveurs', 'Fiable s’il vient de votre passerelle', 'SPF, DKIM, DMARC'],
        ),
        h('Pourquoi de bas en haut ?'),
        p("Chaque serveur ajoute sa ligne **au-dessus** des précédentes. La ligne la plus basse est donc le premier relais. Attention : les lignes les plus basses peuvent être inventées par l'attaquant. Le point de confiance est le dernier `Received` ajouté par **votre** infrastructure : il indique quelle IP vous a réellement remis le message."),
        code('email', 'En-tête à analyser', r`
Received: from mx.contoso.example (mx.contoso.example [192.0.2.25])
        by mail.contoso.example; Thu, 12 Mar 2026 08:41:12 +0000
Received: from mail-relay.fournisseur-paiement.example (unknown [203.0.113.45])
        by mx.contoso.example; Thu, 12 Mar 2026 08:41:10 +0000
Authentication-Results: mx.contoso.example;
        spf=fail smtp.mailfrom=fournisseur-paiement.example;
        dkim=none; dmarc=fail header.from=microsoft.example
From: "Microsoft 365" <no-reply@microsoft.example>
Return-Path: <bounce@fournisseur-paiement.example>
Reply-To: <support@boite-anonyme.example>
Subject: Action requise : votre mot de passe expire aujourd'hui
`),
        tip('Ce que l’on déduit ici', "L'IP de remise est `203.0.113.45`. Le domaine de l'enveloppe, celui du `From` et celui du `Reply-To` sont tous différents, et SPF, DKIM et DMARC ne passent pas. Combiné à l'urgence du sujet, le faisceau est très fort."),
      ],
    },
    {
      id: 'auth',
      title: 'SPF, DKIM et DMARC',
      blocks: [
        table(
          ['Mécanisme', 'Ce qu’il vérifie', 'Sur quel domaine', 'Limite'],
          ['SPF', "L'IP est-elle autorisée à envoyer pour ce domaine ?", '`Return-Path` (enveloppe)', 'Casse lors des transferts ; ne protège pas le `From` visible'],
          ['DKIM', 'La signature est-elle valide, le message intact ?', '`d=` de la signature', 'Ne dit rien de l’intention ; un domaine attaquant peut signer'],
          ['DMARC', 'SPF ou DKIM passe-t-il **et** est-il aligné sur le `From` ?', '`From` visible', 'Dépend de la politique publiée (`p=none`, `quarantine`, `reject`)'],
        ),
        h('Les résultats'),
        table(
          ['Résultat', 'Signification'],
          ['`pass`', 'Vérification réussie'],
          ['`fail`', 'IP explicitement non autorisée (`-all`) ou signature invalide'],
          ['`softfail`', 'IP probablement non autorisée (`~all`) : le domaine ne s’engage pas totalement'],
          ['`neutral`', 'Le domaine ne se prononce pas (`?all`)'],
          ['`none`', 'Aucun enregistrement ou signature'],
          ['`temperror` / `permerror`', 'Erreur temporaire ou de configuration'],
        ),
        code('bash', 'Interroger le DNS', r`
dig +short TXT contoso.example | grep spf
dig +short TXT _dmarc.contoso.example
dig +short TXT selector1._domainkey.contoso.example
`),
        danger('SPF = pass ne veut pas dire légitime', "Un attaquant qui possède `micros0ft-support.example` configure parfaitement SPF, DKIM et DMARC. Un compte réellement compromis chez un fournisseur passe aussi tous les contrôles. Ces mécanismes authentifient un domaine, ils ne jugent pas l'intention."),
        info('L’alignement en une phrase', "DMARC ne passe que si le domaine validé par SPF ou DKIM correspond au domaine du `From`. C'est ce qui explique le cas classique : `spf=pass` sur le domaine de l'attaquant, mais `dmarc=fail` pour le `From` usurpé."),
        warn('Faux positifs', "Newsletters, CRM et outils de facturation envoient pour votre compte : un Return-Path différent est courant (`bounces.mailchimp...`). Les listes de diffusion et les transferts cassent aussi SPF, voire DKIM. Un seul indicateur ne suffit jamais."),
      ],
    },
    {
      id: 'urls',
      title: 'URLs et désobfuscation',
      blocks: [
        table(
          ['Technique', 'Exemple', 'Lecture'],
          ['Typosquatting', '`rnicrosoft.example`', '`rn` au lieu de `m`'],
          ['Sous-domaine trompeur', '`login.microsoft.com.evil.example`', 'Le vrai domaine est `evil.example`'],
          ['Userinfo', '`https://microsoft.com@evil.example/`', 'Tout ce qui précède `@` est ignoré'],
          ['Redirection ouverte', '`https://site-legit.example/r?u=https://evil.example`', 'Passe les filtres grâce au domaine légitime'],
          ['Encodage', '`%2e%2e%2f`, `hxxp`', 'À décoder avant analyse'],
          ['Homoglyphes (IDN)', '`xn--...`', 'Caractères cyrilliques imitant le latin'],
          ['AiTM', '`login-m365.example` qui relaie la vraie page', 'Le jeton de session est volé malgré la MFA'],
        ),
        tip('Défangez avant de partager', "`https://evil.example/a` devient `hxxps[://]evil[.]example/a`. Cela évite les clics accidentels et les aperçus automatiques dans Teams ou Slack, qui préviendraient l'attaquant. L'outil est disponible dans le CyberLab."),
        h('CyberChef : les recettes utiles'),
        table(
          ['Besoin', 'Recette'],
          ['PowerShell encodé', '`From Base64` puis `Decode text (UTF-16LE)`'],
          ['URL encodée', '`URL Decode`'],
          ['Extraire les IOC', '`Extract URLs`, `Extract domains`, `Extract IP addresses`'],
          ['Script compressé', '`From Base64` puis `Gunzip`'],
          ['Défanger', '`Defang URL`'],
        ),
      ],
    },
    {
      id: 'pj',
      title: 'Pièces jointes : analyse statique',
      blocks: [
        table(
          ['Format', 'Pourquoi les attaquants l’aiment', 'Analyse statique'],
          ['`.iso`, `.img`', 'Conteneur : le contenu n’hérite pas toujours du Mark-of-the-Web', 'Monter en lecture seule dans une VM, lister'],
          ['`.lnk`', 'Raccourci qui lance PowerShell, souvent avec une icône de PDF', '`exiftool fichier.lnk`, `LECmd`'],
          ['`.hta`', 'Exécuté par `mshta.exe` avec tous les droits de l’utilisateur', 'Lire comme du texte'],
          ['Office à macros', '`.docm`, `.xlsm`, parfois un ancien `.doc`', '`olevba`, `oledump.py`'],
          ['PDF', 'JavaScript, lanceurs, liens', '`pdfid.py`, `pdf-parser.py`'],
          ['`.zip` chiffré', 'Échappe à l’analyse de la passerelle ; mot de passe dans le mail', 'Ouvrir en sandbox isolée'],
          ['`.one`, `.svg`, `.html`', 'Smuggling HTML, faux formulaire local', 'Lire le code source'],
        ),
        code('bash', 'Analyse sans exécution', r`
# Empreinte et type réel
sha256sum facture.docm && file facture.docm

# Macros : AutoOpen, Shell, URLs
olevba --decode facture.docm

# PDF : /JavaScript, /OpenAction, /Launch
pdfid.py facture.pdf

# Raccourci : cible et arguments
exiftool facture.pdf.lnk

# Chaînes visibles
strings -n 8 charge.bin | grep -Ei 'http|powershell|cmd'
`),
        code('text', 'olevba : ce qu’il faut lire', r`
| AutoExec   | AutoOpen       | Exécution automatique à l'ouverture
| Suspicious | Shell          | Peut lancer une commande
| Suspicious | CreateObject   | Instancie un objet COM (WScript.Shell)
| IOC        | http://...     | URL de la charge
`),
        warn('Mark-of-the-Web', "Windows bloque par défaut les macros des fichiers venant d'Internet grâce au MOTW. Les conteneurs (`.iso`, `.img`, certaines archives) ont longtemps permis de le contourner, d'où leur popularité après 2022."),
      ],
    },
    {
      id: 'opsec',
      title: 'Outils et OPSEC',
      blocks: [
        table(
          ['Outil', 'Usage', 'Risque OPSEC'],
          ['VirusTotal', 'Réputation d’un hash, d’une URL, d’un fichier', 'Tout fichier envoyé devient accessible aux abonnés payants'],
          ['URLScan.io', "Capture d'une page", 'Les scans publics sont indexés : utilisez le mode privé'],
          ['Any.Run', 'Sandbox interactive', 'Les tâches gratuites sont publiques'],
          ['CyberChef', 'Décodage', 'Peut tourner en local : privilégiez cette version'],
        ),
        danger('TLP:RED et confidentialité', "**Ne jamais envoyer un document confidentiel à un scanner public.** Une facture réelle, un contrat ou un mail contenant le nom d'un client deviennent lisibles par des tiers. Commencez par chercher le **hash** : si le fichier est déjà connu, vous obtenez le résultat sans rien divulguer. Sinon, utilisez la sandbox interne."),
        p("L'attaquant surveille aussi : envoyer une URL contenant un jeton unique lié à la victime sur un scanner public, ou la visiter depuis l'IP de votre entreprise, peut lui signaler qu'il est repéré."),
        table(
          ['TLP', 'Diffusion autorisée'],
          ['`TLP:RED`', 'Uniquement les personnes présentes'],
          ['`TLP:AMBER+STRICT`', 'Votre organisation uniquement'],
          ['`TLP:AMBER`', 'Votre organisation et ses clients, si nécessaire'],
          ['`TLP:GREEN`', 'Votre communauté, sans publication'],
          ['`TLP:CLEAR`', 'Sans restriction'],
        ),
        h('Workflow recommandé'),
        ol(
          "Extraire l'en-tête et les IOC sans ouvrir le message dans le client habituel.",
          'Chercher le hash, le domaine et l’IP dans le TIP et sur VirusTotal, sans téléversement.',
          "Analyser statiquement (`olevba`, `pdfid`, `exiftool`).",
          "Détoner si nécessaire dans une sandbox **interne** ou privée, avec une sortie Internet dédiée.",
          "Rechercher dans toute l'entreprise : qui a reçu, qui a cliqué, qui a saisi ses identifiants.",
          'Purger les messages, bloquer les IOC, informer les utilisateurs touchés.',
        ),
        code('kql', 'KQL : portée d’une campagne', r`
EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain == "microsoft.example" or Subject has "votre mot de passe expire"
| summarize Destinataires = dcount(RecipientEmailAddress), Livres = countif(DeliveryAction == "Delivered") by SenderFromAddress, Subject
`),
        code('kql', 'KQL : qui a cliqué ?', r`
UrlClickEvents
| where Timestamp > ago(7d) and Url has "login-m365.example"
| project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough
`),
        ul("La question clé après un clic : **l'utilisateur a-t-il saisi ses identifiants ?** Vérifiez les `SigninLogs` juste après le clic."),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['Réflexe', 'À retenir'],
      ['`Received`', 'De bas en haut. Fiez-vous à la dernière IP vue par votre infrastructure'],
      ['SPF', 'IP autorisée pour le domaine de l’enveloppe'],
      ['DKIM', 'Signature valide pour le domaine `d=`'],
      ['DMARC', 'SPF ou DKIM aligné sur le `From` visible'],
      ['`Reply-To` différent', 'Très suspect dans une demande financière'],
      ['Hash d’abord', 'Cherchez avant de téléverser'],
      ['Clic ≠ compromission', 'Vérifiez la saisie : `SigninLogs`, processus enfant'],
    ),
    code('bash', 'Boîte à outils', r`
olevba --decode fichier.docm          # macros
oledump.py fichier.doc                # flux OLE
pdfid.py fichier.pdf                  # mots-clés PDF
pdf-parser.py -s /JavaScript f.pdf    # extraire le JS
exiftool fichier.lnk                  # cible du raccourci
sha256sum fichier                     # empreinte
`),
  ],
  quiz: [
    {
      q: 'Quelle IP représente la vraie source de remise à votre infrastructure ?',
      evidence: {
        lang: 'email',
        code: 'Received: from mx.contoso.example [192.0.2.25] by mail.contoso.example\nReceived: from unknown [203.0.113.45] by mx.contoso.example\nReceived: from pc [198.51.100.3] by unknown',
      },
      options: ['192.0.2.25', '203.0.113.45', '198.51.100.3', 'Impossible à dire'],
      answer: 1,
      explain: "`mx.contoso.example` est votre serveur : il a réellement vu `203.0.113.45`. La ligne plus basse a été écrite par un relais que vous ne contrôlez pas : elle peut être inventée.",
    },
    {
      q: 'Que signifie cette combinaison ?',
      evidence: { lang: 'email', code: 'spf=pass smtp.mailfrom=envoi-attaquant.example; dkim=none; dmarc=fail header.from=banque.example' },
      options: [
        'Le message est légitime car SPF passe',
        "L'IP est autorisée pour le domaine de l'enveloppe, mais rien n'authentifie le From visible",
        'Le DNS est en panne',
        'DKIM a échoué à cause d’une altération du message par une passerelle, ce qui annule le résultat positif de SPF',
      ],
      answer: 1,
      explain: "SPF valide `envoi-attaquant.example`, pas `banque.example`. C'est précisément le contrôle d'alignement de DMARC qui révèle l'usurpation.",
    },
    {
      q: 'Vers quel domaine mène réellement ce lien ?',
      evidence: { lang: 'text', code: 'https://login.microsoftonline.com.secure-verif.example/auth' },
      options: ['microsoftonline.com', 'login.microsoftonline.com', 'secure-verif.example', 'auth'],
      answer: 2,
      explain: 'Un domaine se lit de droite à gauche : tout ce qui précède `secure-verif.example` n’est qu’un sous-domaine contrôlé par l’attaquant.',
    },
    {
      q: 'Un utilisateur transmet un contrat réel suspect. Quelle est la première étape OPSEC ?',
      options: ['Le téléverser sur VirusTotal', 'Calculer son SHA-256 et rechercher le hash', 'Le téléverser sur Any.Run en mode public', 'L’ouvrir pour lire le contenu'],
      answer: 1,
      explain: "Le hash ne divulgue rien. Le fichier lui-même pourrait contenir des données confidentielles, et tout envoi à un scanner public le rend accessible à des tiers.",
    },
    {
      q: 'Que révèle cette sortie ?',
      evidence: { lang: 'text', code: '| AutoExec   | AutoOpen     | Runs when the Word document is opened\n| Suspicious | Shell        | May run an executable file\n| IOC        | http://203.0.113.50/a.ps1 | URL' },
      options: ['Un document propre', 'Une macro qui s’exécute à l’ouverture et télécharge une charge', 'Un PDF piégé', 'Un fichier chiffré par mot de passe, dont le contenu ne peut pas être lu par l’outil d’analyse'],
      answer: 1,
      explain: "`AutoOpen` et `Shell`, plus une URL de script : c'est le schéma d'une macro de téléchargement.",
    },
    {
      q: 'Pourquoi un `.iso` en pièce jointe est-il suspect ?',
      options: [
        'Il est toujours chiffré',
        "Il sert de conteneur et a longtemps contourné le Mark-of-the-Web, qui bloque les macros",
        'Il ne peut pas être analysé',
        'Il contient forcément un virus, car aucun logiciel légitime n’est jamais distribué sous forme d’image disque',
      ],
      answer: 1,
      explain: "Un utilisateur n'a quasiment jamais besoin de recevoir une image disque par mail. Le contenu pouvait échapper au MOTW, ce qui a popularisé ce format.",
    },
    {
      q: 'Un utilisateur a cliqué sur un lien de phishing. Quelle est la question suivante ?',
      options: ['Quel navigateur utilise-t-il ?', 'A-t-il saisi ses identifiants ? (SigninLogs, jetons, nouvelle IP)', 'Quel est son service ?', 'Le mail contenait-il une image distante permettant à l’expéditeur de savoir qu’il a été ouvert ?'],
      answer: 1,
      explain: "Un clic seul n'implique pas de compromission. La saisie d'identifiants, ou une connexion depuis une IP inconnue juste après, change la gravité.",
    },
  ],
}
