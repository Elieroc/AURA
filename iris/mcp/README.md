# Serveur MCP DFIR-IRIS

Expose DFIR-IRIS comme outils MCP, pour l'investigation interactive (Claude
Code, LLM) : lister/créer des cases, ajouter notes, IOC, assets, tâches,
événements. Pendant du serveur MCP Wazuh (hors dépôt, cf. `.gitignore`), côté
case management.

Serveur retenu : **[srozb/iris-mcp](https://github.com/srozb/iris-mcp)**.
Comparé à `bunnyiesart/mcp-iris` (lecture seule) et `lc-cbot/dfir-iris-mcp`
(Go, minimal), c'est le seul complet en écriture. Il s'appuie sur la
bibliothèque officielle `dfir-iris-client` et FastMCP.

> Note : la **création automatique** de cases par le pipeline (un case par
> incident trié) ne passe PAS par ce serveur MCP — elle est dans
> `ai/soc_agent/iris.py`, en `dfir-iris-client` direct, car déterministe et
> sans boucle d'outils LLM. Ce serveur MCP sert l'investigation *interactive*.

## Installation

Le code upstream est cloné localement et **gitignoré** : on ne versionne pas une
dépendance externe, on épingle sa version. Ici seul ce README est suivi ; le
serveur MCP Wazuh, lui, est entièrement hors dépôt (`/mcp/` dans `.gitignore`).

```bash
git clone https://github.com/srozb/iris-mcp.git iris/mcp/iris-mcp
# Version épinglée validée : 200ef29 (2026-01-28)

# venv dédié, hors dépôt (le dépôt est synchronisé Nextcloud)
python3 -m venv ~/.local/share/soc-ai/iris-mcp-venv
~/.local/share/soc-ai/iris-mcp-venv/bin/pip install -e iris/mcp/iris-mcp
```

`iris_mcp.py` est un module unique : l'install éditable ne l'expose pas sur le
`sys.path`, on lance donc le fichier directement (Python ajoute son dossier au
path, les dépendances sont dans le venv).

## Enregistrement (stdio)

Transport stdio par défaut. Clé d'API passée en variable d'environnement, pas
dans un fichier versionné — scope `local` :

```bash
set -a; source iris/.env; set +a
claude mcp add iris --scope local \
  --env IRIS_HOST=https://127.0.0.1:8443 \
  --env IRIS_API_KEY="$IRIS_ADM_API_KEY" \
  --env IRIS_VERIFY_SSL=false \
  -- ~/.local/share/soc-ai/iris-mcp-venv/bin/python \
     "$(pwd)/iris/mcp/iris-mcp/iris_mcp.py"

claude mcp list | grep iris     # doit afficher ✔ Connected
```

`IRIS_VERIFY_SSL=false` : certificat auto-signé sur la loopback (cf.
`iris/README.md`). À revoir si IRIS est exposé au LAN.

## Vérification

Dans une session Claude Code, les outils `mcp__iris__*` deviennent
disponibles : `list_cases`, `create_case`, `add_note`, `add_ioc`, `add_asset`,
`add_task`, `add_event`, plus les catalogues de types (`list_ioc_types`,
`list_severities`…). Utile pour enrichir ou fouiller un case à la main pendant
une investigation.
