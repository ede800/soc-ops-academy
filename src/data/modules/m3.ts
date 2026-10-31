import type { Module } from '../../types'
import { code, danger, h, info, p, r, table, tip, ul, warn } from '../blocks'

export const m3: Module = {
  id: 'reseau-linux',
  number: 3,
  title: 'Analyse réseau, flux et logs Linux',
  tier: 'N1-N2',
  summary:
    'Lire des flux TCP/UDP, repérer scans, beaconing et tunnels DNS avec Zeek et Suricata, puis enquêter sur un serveur Linux et ses journaux web.',
  objectives: [
    'Interpréter les flags TCP et reconnaître un scan',
    'Repérer un C2 par la régularité de ses connexions',
    'Reconnaître un tunnel DNS et une exfiltration',
    'Enquêter dans `auth.log`, `auditd`, `cron` et les logs web',
    'Identifier SQLi, LFI, RCE et web shell dans un `access.log`',
  ],
  sections: [
    {
      id: 'tcp',
      title: 'Flux TCP/UDP et scans de ports',
      blocks: [
        table(
          ['Séquence', 'Signification', 'Lecture SOC'],
          ['`SYN` → `SYN-ACK` → `ACK`', 'Connexion établie', 'Port ouvert'],
          ['`SYN` → `RST`', 'Port fermé', 'En masse : scan'],
          ['`SYN` sans réponse', 'Filtré par un pare-feu', 'Normal à l’extérieur, curieux en interne'],
          ['`FIN` → `FIN-ACK`', 'Fermeture normale', 'Rien à signaler'],
          ['`RST` en cours de session', 'Coupure brutale', 'IPS, pare-feu ou application qui plante'],
        ),
        h('Zeek : les états de connexion (conn_state)'),
        table(
          ['État', 'Signification', 'Lecture SOC'],
          ['`S0`', 'SYN envoyé, aucune réponse', 'Beaucoup de S0 vers des ports distincts : scan furtif'],
          ['`REJ`', 'SYN puis RST', 'Port fermé, scan si répété'],
          ['`SF`', 'Établie et fermée proprement', 'Connexion normale'],
          ['`RSTO` / `RSTR`', 'Reset par l’initiateur ou le répondeur', 'À corréler'],
          ['`OTH`', 'Aucun SYN vu', 'Capture partielle ou trafic asymétrique'],
        ),
        code('bash', 'Zeek : top des sources ayant échoué vers de nombreux ports', r`
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p conn_state \
  | awk '$4=="S0" || $4=="REJ" {print $1, $2, $3}' | sort -u \
  | awk '{count[$1" -> "$2]++} END {for (k in count) if (count[k] > 100) print count[k], k}' \
  | sort -rn
`),
        warn('Faux positifs', "Les scanners de vulnérabilités (Nessus, Qualys), la supervision et certains outils de découverte réseau génèrent le même trafic qu'un attaquant. Maintenez la liste de leurs IP. Un scan **interne** depuis un poste utilisateur reste un signal fort de mouvement latéral."),
      ],
    },
    {
      id: 'beaconing',
      title: 'C2 beaconing',
      blocks: [
        p("Un implant contacte son serveur à intervalles réguliers pour recevoir ses ordres. Un humain qui navigue produit un trafic irrégulier ; un implant produit un rythme. Le jitter ajoute du hasard à l'intervalle, sans masquer la tendance."),
        code('log', 'Proxy : intervalle de 60 s avec environ 10 % de jitter', r`
09:14:22 FIN-PC-042 GET https://cdn-sync-update.example/api/v2/status 200 312
09:15:25 FIN-PC-042 GET https://cdn-sync-update.example/api/v2/status 200 312
09:16:21 FIN-PC-042 GET https://cdn-sync-update.example/api/v2/status 200 312
09:17:24 FIN-PC-042 GET https://cdn-sync-update.example/api/v2/status 200 312
09:18:19 FIN-PC-042 POST https://cdn-sync-update.example/api/v2/result 200 48211
`),
        ul(
          "**Régularité** : écart-type faible entre les connexions.",
          "**Taille constante** : réponses de même taille tant qu'aucun ordre n'est reçu.",
          "**Durée** : le trafic continue la nuit et le week-end, session verrouillée.",
          "**Rareté** : peu de machines de l'entreprise contactent ce domaine.",
          "**Ratio** : un POST volumineux après une longue série de GET courts peut signer l'envoi d'un résultat.",
        ),
        code('kql', 'KQL : détecter la régularité', r`
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteUrl != ""
| order by DeviceName asc, RemoteUrl asc, Timestamp asc
| extend Delta = iff(prev(DeviceName) == DeviceName and prev(RemoteUrl) == RemoteUrl, datetime_diff('second', Timestamp, prev(Timestamp)), int(null))
| where isnotnull(Delta) and Delta > 0
| summarize Hits = count(), Avg = avg(Delta), Dev = stdev(Delta) by DeviceName, RemoteUrl
| where Hits > 50 and Dev / Avg < 0.2
| order by Hits desc
`),
        code('spl', 'SPL : équivalent', r`
index=proxy earliest=-24h
| sort 0 src dest _time
| streamstats current=f last(_time) as prev by src dest
| eval delta = _time - prev
| stats count avg(delta) as avg stdev(delta) as dev by src dest
| where count > 50 AND dev / avg < 0.2
| sort - count
`),
        warn('Beaucoup de logiciels légitimes « beaconnent »', "Windows Update, agents EDR, Teams, antivirus et clients de synchronisation ont un rythme très régulier. Écartez-les par une liste d'autorisation, puis concentrez-vous sur les domaines rares, récents ou contactés par un processus inattendu."),
        h('Proxy HTTP : autres indices'),
        table(
          ['Indice', 'Exemple', 'Commentaire'],
          ['User-Agent', '`python-requests/2.31`, `curl/8.0`, `Mozilla/4.0` seul', 'Un UA très ancien ou absent ressort sur un poste de bureau'],
          ['Méthode', 'POST vers un domaine jamais vu', 'Exfiltration ou résultat de commande'],
          ['Code', '`CONNECT` direct vers une IP', 'Le trafic légitime passe rarement par une IP brute'],
          ['Catégorie', 'Nouveau domaine, DNS dynamique', 'Bloquez si possible la catégorie « newly registered »'],
        ),
      ],
    },
    {
      id: 'dns',
      title: 'DNS tunneling et exfiltration',
      blocks: [
        p("Le DNS sort presque partout, même depuis les réseaux restreints. L'attaquant encode ses données dans les sous-domaines et reçoit ses réponses via des enregistrements `TXT` ou `NULL`."),
        code('log', 'Zeek dns.log : schéma de tunnel', r`
query=aGVsbG8gZnJvbSB2aWN0aW0.s1.tunnel-exemple.example qtype=TXT rcode=NOERROR
query=dGhpcyBpcyBleGZpbHRyYXRlZA.s2.tunnel-exemple.example qtype=TXT rcode=NOERROR
query=ZGF0YSBwYXJ0IDAwMDAwMDAzCg.s3.tunnel-exemple.example qtype=TXT rcode=NOERROR
`),
        table(
          ['Indicateur', 'Normal', 'Tunnel'],
          ['Longueur du sous-domaine', 'Moins de 20 caractères', 'Souvent plus de 40'],
          ['Entropie', 'Mots lisibles', 'Aléatoire, Base32/Base64'],
          ['Sous-domaines uniques par domaine', 'Quelques-uns', 'Des milliers'],
          ['Type de requête', 'Majorité de `A` / `AAAA`', 'Beaucoup de `TXT`, `NULL`, `CNAME`'],
          ['Volume', 'Modeste', 'Élevé vers un seul domaine'],
        ),
        code('kql', 'KQL : sous-domaines uniques par domaine', r`
DnsEvents
| where SubType == "LookupQuery"
| extend Parts = split(Name, ".")
| extend Root = strcat(Parts[array_length(Parts) - 2], ".", Parts[array_length(Parts) - 1])
| summarize Unique = dcount(Name), AvgLen = avg(strlen(Name)) by Root, ClientIP
| where Unique > 500 and AvgLen > 40
| order by Unique desc
`),
        code('bash', 'Zeek : volumes par domaine', r`
cat dns.log | zeek-cut query | awk -F. 'NF>=2 {print $(NF-1)"."$NF}' | sort | uniq -c | sort -rn | head -20
`),
        info('Faux positifs connus', "Les antivirus (requêtes de réputation), les CDN, certains services de télémétrie et les enregistrements DKIM produisent des noms longs ou à forte entropie. Basez-vous sur une combinaison de critères, et non sur la longueur seule."),
        tip('Exfiltration : pensez en volumes', "Comparez les octets envoyés aux octets reçus. Un poste qui envoie 4 Go vers un service de stockage jamais utilisé à 3 h du matin mérite un ticket, même si le domaine a bonne réputation."),
      ],
    },
    {
      id: 'linux',
      title: 'Logs Linux',
      blocks: [
        table(
          ['Fichier', 'Contenu', 'Distribution'],
          ['`/var/log/auth.log`', 'SSH, sudo, su', 'Debian, Ubuntu'],
          ['`/var/log/secure`', 'Idem', 'RHEL, CentOS, Fedora'],
          ['`/var/log/syslog` ou `messages`', 'Système général', 'Respectivement Debian, RHEL'],
          ['`/var/log/audit/audit.log`', 'Auditd : `EXECVE`, accès fichiers', 'Selon configuration'],
          ['`/var/log/cron` ou syslog', 'Tâches exécutées', 'Selon distribution'],
          ['`/var/log/wtmp`, `btmp`, `lastlog`', 'Connexions (binaires)', 'Lire avec `last`, `lastb`, `lastlog`'],
          ['`~/.bash_history`', 'Commandes', 'Facilement effacé : son absence est un indice'],
        ),
        h('Brute-force SSH'),
        code('log', 'auth.log : du brute-force au succès', r`
Mar 12 03:12:41 web01 sshd[2211]: Failed password for root from 203.0.113.77 port 51122 ssh2
Mar 12 03:12:43 web01 sshd[2213]: Failed password for invalid user admin from 203.0.113.77 port 51124 ssh2
Mar 12 03:14:02 web01 sshd[2290]: Accepted password for deploy from 203.0.113.77 port 51301 ssh2
Mar 12 03:14:40 web01 sudo: deploy : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash sysbackup
Mar 12 03:15:02 web01 useradd[2301]: new user: name=sysbackup, UID=1002, GID=1002, home=/home/sysbackup
`),
        code('bash', 'Commandes de terrain', r`
# Top des IP en échec
grep "Failed password" /var/log/auth.log | grep -oE 'from [0-9.]+' | sort | uniq -c | sort -rn | head

# Le plus important : une IP qui échoue PUIS réussit
grep "Accepted" /var/log/auth.log

# Sudo et créations de comptes
grep -E "sudo:|useradd|usermod" /var/log/auth.log

# Connexions récentes et tentatives échouées
last -a | head -20 ; lastb -a | head -20

# Comptes UID 0 (seul root attendu) et persistance
awk -F: '$3==0 {print $1}' /etc/passwd
crontab -l ; ls -la /etc/cron.* ; ls -la ~/.ssh/authorized_keys

# Auditd : commandes de www-data
ausearch -ua www-data -m EXECVE -i | tail -50
`),
        code('log', 'auditd : exécution par le compte web', r`
type=SYSCALL msg=audit(1773285222.451:9921): arch=c000003e syscall=59 success=yes uid=33 comm="sh" exe="/usr/bin/dash"
type=EXECVE msg=audit(1773285222.451:9921): argc=3 a0="sh" a1="-c" a2="id;uname -a;cat /etc/passwd"
`),
        warn('Le bruit SSH', "Tout SSH exposé sur Internet reçoit des milliers de tentatives par jour. L'échec seul a peu de valeur : le vrai signal, c'est un **succès** depuis une IP qui échouait juste avant, ou depuis un pays inhabituel."),
      ],
    },
    {
      id: 'web',
      title: 'Logs web et web shells',
      blocks: [
        table(
          ['Attaque', 'Signature dans access.log', 'Exemple'],
          ['SQLi', '`UNION SELECT`, `OR 1=1`, `SLEEP(`', '`/produit.php?id=1%27%20UNION%20SELECT...`'],
          ['LFI', '`../`, `/etc/passwd`, `php://filter`', '`/index.php?page=../../../../etc/passwd`'],
          ['RFI', 'URL dans un paramètre', '`/index.php?page=http://203.0.113.5/s.txt`'],
          ['RCE', '`;id`, `|whoami`, `${jndi:`', '`/cgi-bin/x.cgi?c=;id`'],
          ['Web shell', 'POST sur un script récent dans un dossier d’upload', '`POST /uploads/shell.php 200`'],
        ),
        code('log', 'access.log : une compromission complète', r`
203.0.113.9 - - [12/Mar/2026:10:01:12 +0000] "POST /upload.php HTTP/1.1" 200 412 "-" "Mozilla/5.0"
203.0.113.9 - - [12/Mar/2026:10:01:20 +0000] "GET /uploads/img_442.php?cmd=id HTTP/1.1" 200 54 "-" "python-requests/2.31"
203.0.113.9 - - [12/Mar/2026:10:01:34 +0000] "GET /uploads/img_442.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1877 "-" "python-requests/2.31"
203.0.113.9 - - [12/Mar/2026:10:02:03 +0000] "POST /uploads/img_442.php HTTP/1.1" 200 88 "-" "python-requests/2.31"
`),
        danger('Le code 200 change tout', "Un `/uploads/shell.php` en `404` est un scan automatique, à ignorer dans la plupart des cas. En `200`, le fichier existe et il a répondu : c'est un incident. Un SQLi en `500` puis en `200` avec une grande taille de réponse est également à creuser."),
        code('bash', 'Commandes de terrain', r`
# Un .php exécuté depuis un dossier d'upload
grep -E 'uploads?/.*\.php' access.log | awk '$9==200'

# Top des IP et User-Agents
awk '{print $1}' access.log | sort | uniq -c | sort -rn | head
awk -F'"' '{print $6}' access.log | sort | uniq -c | sort -rn | head

# Fichiers web récents (24 h)
find /var/www -type f -name '*.php' -mtime -1 -ls
`),
        info('Limite importante', "Les corps de POST ne figurent pas dans `access.log`. Un web shell piloté uniquement en POST n'y laisse que le chemin, le code et la taille : `auditd` et l'EDR (processus enfants de `www-data` ou d'`apache2`) complètent le tableau."),
      ],
    },
  ],
  cheatSheet: [
    table(
      ['Signal', 'À retenir'],
      ['`S0` / `REJ` en masse', 'Scan de ports'],
      ['Intervalle régulier + domaine rare', 'Beaconing C2'],
      ['Sous-domaines longs, `TXT`, volume', 'Tunnel DNS'],
      ['Échecs puis `Accepted`', 'Brute-force SSH réussi'],
      ['UID 0 autre que root', 'Compte backdoor'],
      ['`200` sur `.php` dans `/uploads/`', 'Web shell'],
      ['`www-data` → `sh`', 'RCE ou web shell'],
    ),
    code('bash', 'Tshark et Zeek express', r`
# Hôtes qui échangent le plus
tshark -r capture.pcap -q -z conv,ip

# Requêtes DNS
tshark -r capture.pcap -Y dns.flags.response==0 -T fields -e ip.src -e dns.qry.name

# Requêtes HTTP
tshark -r capture.pcap -Y http.request -T fields -e ip.src -e http.host -e http.request.uri -e http.user_agent

# Zeek : top des domaines HTTP
cat http.log | zeek-cut host | sort | uniq -c | sort -rn | head
`),
  ],
  quiz: [
    {
      q: 'Que montre cet extrait Zeek ?',
      evidence: { lang: 'log', code: 'conn_state=S0 id.orig_h=10.20.4.42 id.resp_h=10.20.8.5 id.resp_p=21,22,23,25,80,135,139,443,445,3389 (+ 900 ports en 40 s)' },
      options: ['Une navigation web', 'Un scan de ports interne depuis un poste', 'Un transfert SMB', 'Un tunnel DNS'],
      answer: 1,
      explain: "Le même hôte teste près de 1000 ports en 40 secondes sans réponse. Depuis un poste, sans lien avec un scanner autorisé, c'est un indice de reconnaissance interne.",
    },
    {
      q: 'Quel est le meilleur indicateur de beaconing ?',
      options: ['Beaucoup de trafic vers Microsoft pendant les heures de bureau, surtout en provenance de postes administrateurs', 'Des connexions à intervalle quasi constant vers un domaine rare', 'Un code HTTP 404', 'Un User-Agent Chrome à jour'],
      answer: 1,
      explain: "La régularité combinée à la rareté du domaine est le critère principal. Le volume seul ne distingue pas un implant d'une mise à jour légitime.",
    },
    {
      q: 'Que voyez-vous ici ?',
      evidence: { lang: 'log', code: 'query=ZGF0YSBwYXJ0IDAwMDAwMDAzCg.s3.tunnel-exemple.example qtype=TXT (+ 4 200 sous-domaines uniques en 1 h)' },
      options: ['Un enregistrement DKIM normal', 'Une résolution CDN', 'Un tunnel DNS probable', 'Un scan de ports'],
      answer: 2,
      explain: 'Sous-domaine encodé, type `TXT` et milliers de valeurs uniques vers un seul domaine : le schéma typique d’un tunnel.',
    },
    {
      q: 'Dans ce journal, quelle ligne doit vous faire réagir en priorité ?',
      evidence: { lang: 'log', code: 'Failed password for root from 203.0.113.77 (x340)\nAccepted password for deploy from 203.0.113.77\nsudo: deploy : COMMAND=/usr/sbin/useradd -m sysbackup' },
      options: ['Les échecs sur root', 'Le succès de deploy depuis la même IP, suivi de la création de compte', 'Rien, le bruit SSH est normal sur Internet et aucune de ces lignes ne mérite qu’on s’y arrête', 'Le port SSH'],
      answer: 1,
      explain: "Les échecs sont du bruit courant. Le succès depuis cette même IP et la création d'un compte pour la persistance constituent la compromission.",
    },
    {
      q: 'Quelle ligne prouve le mieux une exécution de web shell ?',
      options: [
        '`GET /shell.php 404`',
        '`GET /wp-login.php 200` depuis un navigateur Chrome à jour et une IP interne connue',
        '`GET /uploads/img_442.php?cmd=id 200` avec `python-requests`',
        '`GET /index.html 200`',
      ],
      answer: 2,
      explain: 'Un script PHP dans un dossier d’upload, un paramètre de commande, un code 200 et un UA de script : le fichier existe et il exécute des ordres.',
    },
    {
      q: 'Pourquoi une auditd `EXECVE` avec `uid=33` et `a2="id;uname -a"` est-elle si parlante ?',
      options: [
        'Car uid=33 est root',
        'Car le compte web (`www-data`) lance un shell et des commandes de reconnaissance',
        'Car `uname` est interdit',
        'Car auditd est obsolète et ne journalise un appel EXECVE que lorsque le système est déjà compromis',
      ],
      answer: 1,
      explain: "L'UID 33 correspond à `www-data` sur Debian et Ubuntu. Un service web n'a pas à lancer `sh -c` avec des commandes de reconnaissance.",
    },
    {
      q: 'Pourquoi `access.log` ne suffit-il pas pour un web shell piloté en POST ?',
      options: ['Il n’enregistre pas les POST', 'Il n’enregistre pas le corps de la requête', 'Il supprime les 200', 'Il enregistre uniquement les IP internes'],
      answer: 1,
      explain: 'Le POST est bien visible, mais sans son contenu. Pour voir les commandes, il faut auditd, l’EDR ou un WAF qui journalise les corps.',
    },
  ],
}
