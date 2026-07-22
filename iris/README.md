# DFIR-IRIS — case management

Plateforme de gestion des cas d'incident du SOC. C'est ici qu'atterrissent les
alertes HIGH/CRITICAL triées par l'IA : un case par incident, avec sa timeline,
ses IOC, ses assets et la trace des actions automatiques.

UI : <https://localhost:8443> — API : même hôte, endpoints `/manage/*`.

## Pourquoi IRIS et pas TheHive

TheHive 5 réserve une partie de ses fonctions à la licence commerciale et
s'appuie sur Cassandra + Elasticsearch, soit 6 à 8 Go de RAM. Sur cet hôte
(30 Go partagés avec Wazuh, Shuffle et bientôt le runtime LLM), c'était
disqualifiant. IRIS est intégralement open source et tient en ~650 Mo avec
Postgres.

## Installation

```bash
cd iris
cp .env.example .env

# Générer un secret différent pour chaque __CHANGE_ME__ :
#   openssl rand -hex 32
# Puis décommenter et remplir IRIS_ADM_PASSWORD et IRIS_ADM_API_KEY.
$EDITOR .env

./scripts/generate-certs.sh      # PKI locale (demande sudo, cf. plus bas)
docker compose up -d
```

Premier démarrage : ~40 s (migrations de schéma + enregistrement des modules).
Attendre la bannière :

```bash
docker compose logs app | grep "IRIS IS READY"
```

Si `IRIS_ADM_PASSWORD` est resté vide, IRIS génère un mot de passe aléatoire
affiché **une seule fois** dans ces mêmes logs.

> Les identifiants admin ne sont créés qu'au **tout premier** démarrage. Les
> changer dans `.env` après coup n'a aucun effet : il faut soit les modifier
> depuis l'UI, soit repartir de zéro avec `docker compose down -v` (ce qui
> détruit toutes les cases).

## Vérification

```bash
set -a; source .env; set +a
curl -sk -H "Authorization: Bearer ${IRIS_ADM_API_KEY}" https://127.0.0.1:8443/api/ping
# {"status": "success", "message": "pong", "data": []}
```

## Choix d'implémentation

### Port 8443

443 est déjà occupé par le dashboard Wazuh sur cet hôte. `INTERFACE_HTTPS_PORT`
est propagé jusqu'au `listen` de nginx par son entrypoint, donc changer la
valeur dans `.env` suffit — pas de mapping de ports à décaler.

### Certificats

`scripts/generate-certs.sh` fabrique notre propre CA et notre certificat
serveur. Le dépôt upstream d'iris-web versionne des certificats de
développement **clé privée comprise** : elle est publique sur GitHub, donc
inutilisable ailleurs qu'en démo jetable.

Le script demande un `sudo` pour une seule opération : `chown 33:33` sur la clé
serveur. nginx tourne en `www-data` (uid 33) dans le conteneur, et on préfère
lui donner la clé en 640 plutôt que de la passer en 644, ce qui la rendrait
lisible par n'importe quel compte de l'hôte.

Le navigateur signalera un émetteur inconnu tant que
`certificates/rootCA/irisRootCACert.pem` n'est pas importé dans son magasin.

### Exposition réseau

nginx est bindé sur `127.0.0.1` par défaut (`IRIS_BIND_ADDR`). IRIS contient
les cases, les IOC et les notes d'investigation, c'est-à-dire la cartographie
complète de nos incidents. Pour y accéder depuis le LAN, changer la variable
*et* remplacer le certificat auto-signé.

### Concurrence Celery

Le worker est lancé avec `-c 2` via un `command` qui court-circuite
`iris-entrypoint.sh`. Sans ça, Celery démarre un process par cœur (16 ici),
réclame ~780 Mo au repos et se fait OOM-kill — pour une charge réelle de
quelques tâches par heure. Les cœurs sont réservés au LLM.

L'entrypoint honorait `NUMBER_OF_CHILD` jusqu'en v2.4.20 ; depuis, celery y est
câblé en dur. **À revérifier à chaque montée de version :**

```bash
docker run --rm --entrypoint cat ghcr.io/dfir-iris/iriswebapp_app:<tag> \
    /iriswebapp/iris-entrypoint.sh
```

### Version épinglée

`IRIS_VERSION` fige les quatre images sur une release. IRIS applique ses
migrations de schéma au démarrage : un `latest` qui bouge migrerait la base
sans qu'on l'ait décidé, et les migrations sont irréversibles. Sauvegarder le
volume `db_data` avant toute montée de version.

## API — à savoir avant d'écrire le soc-agent

**La v2.4.27 n'expose pas `/api/v2`.** Ces routes renvoient 404 ; l'API en
service est la « legacy » sous `/manage/*` (`api_current` 2.0.5, vérifiable sur
`GET /api/versions`).

Authentification par `Authorization: Bearer <IRIS_ADM_API_KEY>`. La plupart des
endpoints exigent un paramètre `?cid=<case_id>` désignant le case courant, même
lorsque l'opération n'y touche pas.

Création d'un case :

```bash
curl -sk -X POST "https://127.0.0.1:8443/manage/cases/add?cid=1" \
  -H "Authorization: Bearer ${IRIS_ADM_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"case_name":"...","case_description":"...","case_customer":1,"case_soc_id":"..."}'
```

Le soc-agent utilisera de préférence la bibliothèque `dfir-iris-client`, qui
encapsule ces routes.

> La clé d'API actuelle est celle de l'administrateur. Avant d'y brancher le
> soc-agent, créer un compte de service dédié avec les seuls droits nécessaires
> (création de case, ajout de note/IOC) : le soc-agent traite des logs
> contrôlés par l'attaquant, il ne doit pas porter un jeton admin.

## Empreinte mémoire

| Conteneur | Limite | Au repos |
|---|---|---|
| `iris-app` | 1 Go | ~170 Mo |
| `iris-worker` | 512 Mo | ~260 Mo |
| `iris-rabbitmq` | 384 Mo | ~155 Mo |
| `iris-db` | 512 Mo | ~40 Mo |
| `iris-nginx` | 128 Mo | ~17 Mo |
| **Total** | | **~645 Mo** |

Les `mem_limit` sont explicites pour éviter qu'un pic d'un service n'aille
OOM-killer un voisin — le runtime LLM occupera bientôt la moitié de la RAM.

## Exploitation

```bash
docker compose ps
docker compose logs -f app
docker compose restart worker

# Sauvegarde de la base (avant montée de version)
docker exec iris-db pg_dump -U postgres iris_db | gzip > iris-$(date +%F).sql.gz
```

`docker compose down -v` **détruit toutes les cases** : le `-v` supprime le
volume `db_data`.
