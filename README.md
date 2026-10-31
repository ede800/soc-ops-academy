# SOC Ops Academy

Plateforme d'entraînement opérationnel SOC, en français : du triage N1 au threat hunting N3.

- **7 modules** : cours, cheat sheet de terrain et quiz à partir de preuves
- **Live SOC Queue** : 8 tickets jouables (logs bruts, arbre de processus, threat intel, décision, rapport corrigé)
- **SOC CyberLab** : décodeur PowerShell Base64 UTF-16LE, defang/refang, extracteur d'IOC, analyseur d'en-têtes email
- **Explorateur MITRE ATT&CK** : techniques par tactique avec méthode, logs et requêtes KQL/SPL
- **5 playbooks** interactifs, **générateur de rapport** Markdown et **recherche globale** (`Ctrl+K`)
- Progression, XP et rangs sauvegardés dans le `localStorage` du navigateur

Site 100 % statique : aucune donnée ne quitte le navigateur.

## Développement

```bash
npm install
npm run dev        # serveur local
npm test           # tests unitaires et intégrité du contenu
npm run typecheck  # npx tsc --noEmit
npm run build      # vérification des types puis génération dans dist/
```

## Publication sur GitHub Pages

1. Poussez le dépôt sur GitHub, branche `main`.
2. Dans **Settings > Pages > Build and deployment > Source**, choisissez **GitHub Actions**.

Le workflow `.github/workflows/deploy.yml` teste, compile et publie à chaque push. Le site fonctionne quel que soit le nom du dépôt (`base: './'`), et le routage par hash évite les erreurs 404 sur les liens profonds.

## Structure du contenu

| Fichier | Contenu |
|---|---|
| `src/data/modules/` | Les 7 modules de cours |
| `src/data/siemAlerts.ts` | Les 8 tickets et leur correction |
| `src/data/mitre.ts` | Les techniques ATT&CK et leurs requêtes |
| `src/data/playbooks.ts` | Les 5 playbooks |
| `src/data/cheatSheets.ts` | Event IDs, Sysmon, ports, LOLBins, codes d'erreur |

## Notes

- Les scénarios sont fictifs. Les IP utilisent les plages réservées à la documentation (RFC 5737) et les domaines le TLD `.example` (RFC 2606). Les hash sont inventés.
- Les requêtes sont des points de départ : les noms d'index, de tables et de champs varient selon les environnements. Testez-les avant toute mise en production.
- Le rapport d'investigation est corrigé par heuristique (structure et présence des preuves attendues), pas par une lecture humaine.
