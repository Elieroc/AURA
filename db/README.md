# `db/` — données persistantes des moteurs de stockage

Tout ce que les bases écrivent sur disque vit ici, en bind mount depuis le
`docker-compose.yml` de la racine. Rien n'est versionné : le contenu de ces
dossiers, ce sont les alertes, les incidents et les cases du SOC.

Il n'y a **aucune commande à lancer** avant le premier `docker compose up -d` :
le service `aura-init` crée les cinq dossiers et pose le bon propriétaire là où
c'est nécessaire.

| Dossier | Conteneur | Contenu | uid attendu |
|---|---|---|---|
| `socagent-postgres/` | `socagent-db` (postgres:16) | base du pipeline IA : alertes ingérées, incidents, verdicts de triage, whitelist, baseline UEBA, CMDB, mitigations | root (postgres chown lui-même) |
| `iris-postgres/` | `iris-db` (DFIR-IRIS) | cases, timeline, IOC, tâches, notes d'investigation | root (postgres chown lui-même) |
| `wazuh-indexer/` | `wazuh.indexer` (OpenSearch) | index des alertes Wazuh de tout le parc — le plus gros volume du stack | **1000:1000** |
| `shuffle-opensearch/` | `shuffle-opensearch` (OpenSearch) | état des workflows et des exécutions Shuffle | **1000:1000** |
| `misp-mariadb/` | `misp-db` (MariaDB) | événements, attributs et IOC de MISP | root (MariaDB chown lui-même) |

## Deux pièges qui expliquent la forme de ce dossier

**Un dossier vide ne se versionne pas — et surtout, il doit le rester.** Le
réflexe habituel (un `.gitkeep` par dossier) est ici un piège : `initdb` refuse
un data dir non vide (`directory exists but is not empty`) et le moindre fichier
témoin dans `socagent-postgres/` ou `iris-postgres/` casse le premier
démarrage. D'où ce README unique à la racine de `db/`, et jamais un fichier dans
les sous-dossiers.

**Docker crée les bind mounts manquants, mais en `root:root`.** Ça convient à
Postgres et à MariaDB, dont l'entrypoint démarre root et corrige le
propriétaire. Ça ne convient pas aux deux OpenSearch, qui tournent en uid 1000
et échouent sur `AccessDeniedException` sans jamais chown quoi que ce soit. Le
`chown 1000:1000` de `aura-init` ne concerne que ces deux-là.

## Sauvegarde

Un `docker compose down` ne touche à rien ici. Pour repartir de zéro sur une
base, arrêter le stack puis supprimer le dossier correspondant : il sera
recréé vide au `up` suivant, et le moteur le réinitialisera.
