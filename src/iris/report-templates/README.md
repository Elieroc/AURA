# Templates de rapport IRIS

Templates Jinja2 rendus par DFIR-IRIS depuis un case (bouton **Generate report**
→ type *Investigation*). À ne pas confondre avec les *case templates* d'IRIS,
qui pré-remplissent un case à sa création — le soc-agent construit ses cases en
code (`src/ai/soc_agent/iris.py`), il n'en utilise aucun.

| Fichier | Type | Langue | Contenu |
|---|---|---|---|
| `incident-technique-fr.md` | Investigation | FR | Rapport DFIR complet : synthèse, note d'analyse IA, machines, IOC, chronologie, remédiations, preuves |

## Déploiement

```bash
IRIS_URL=https://127.0.0.1:8443 \
IRIS_API_KEY=<clé d'un compte server_administrator> \
  ../scripts/deploy-report-template.sh incident-technique-fr.md
```

Le script supprime l'entrée de même nom avant de recréer : IRIS n'a **pas**
d'endpoint de mise à jour, `add` empile des doublons. L'id du template change
donc à chaque déploiement — ne pas le câbler en dur ailleurs.

Le fichier est copié dans le volume `user_templates`, partagé entre `iris-app`
et `iris-worker` (la génération peut tourner côté worker).

## Contexte Jinja disponible

Produit par `app/datamgmt/reporter/report_db.py: export_case_json_for_report()`
(IRIS v2.4.27) :

- `case` — `name`, `description`, `open_date`, `close_date`, `case_uuid`,
  `soc_id`, `status_name`, `state.state_name`, `severity.severity_name`,
  `classification.name`, `client.customer_name`, `owner.user_name`,
  `tags[].tag_title` (le soc-agent y met le hostname)
- `assets[]` — `asset_name`, `type`, `asset_ip`, `asset_description`,
  `asset_compromise_status`, `analysis_status`, `asset_ioc[]`
- `iocs[]` — `ioc_value`, `ioc_type.type_name`, `ioc_description`, `ioc_tags`
- `timeline[]` — `event_date`, `event_title`, `event_content`, `event_source`,
  `event_tags`, `assets[]` (chaînes « nom (type) »), `iocs[]`,
  `event_in_summary` (posé à vrai par le soc-agent pour les alertes ≥ niveau 10)
- `tasks[]` — `task_title`, `task_status`, `task_description`, `task_tags`,
  `task_open_date`, `task_close_date`, `task_assignees[]`
- `notes[]` — `note_title`, `note_content`, `directory.name`, `comments[]`
- `evidences[]` — `filename`, `file_hash`, `file_size`, `date_added`, `added_by`
- `doc_id`, `date`, `user`, `export_date`

## Pièges (vérifiés sur v2.4.27, prod)

- **Dates de types mélangés.** `case.*` et `notes.*` passent par marshmallow →
  chaînes ; `timeline`, `tasks`, `assets`, `evidences` sortent de `_asdict()` →
  `datetime`. D'où la macro `dt()`, qui teste `v.strftime is defined`.
- **`evidences` n'exporte pas la description.** Le corps riche posé par
  `iris._evidences` (full_log, JSON brut, deep-link Discover) reste dans IRIS et
  n'est pas atteignable depuis un template : on ne peut lister que nom, hash,
  taille, date.
- **Environnement sandboxé** (`IrisJinjaEnv`) : attributs dunder interdits,
  appel d'un type interdit. Appeler une méthode d'instance (`strftime`) passe.
- **Titres de notes.** Le rapport d'analyse du soc-agent commence en `#` ; sans
  rétrogradation (macro `corps()`), ses sections écrasent le plan du rapport.
- **`notes` est une liste plate**, le répertoire est dans `note.directory.name`
  (`Analyse IA` pour les notes du soc-agent).
- **Markdown en tableau** : filtrer les `\n` et échapper les `|`, sinon la
  table se disloque (macro `cell()`).
- **Nom de fichier généré** : `%case_name%` est évité dans le format de nommage,
  un `/` dans un titre de case casserait le chemin d'écriture.

## Tester un template sans le déployer

```bash
# depuis l'hôte IRIS
docker cp mon-template.md iris-app:/tmp/tpl.md
docker exec -e PYTHONPATH=/iriswebapp iris-app python - <<'EOF'
from app import app
from app.models.authorization import User
from flask_login import login_user
from app.iris_engine.utils.common import IrisJinjaEnv
from app.datamgmt.reporter.report_db import export_case_json_for_report
CID = 184
with app.app_context():
    with app.test_request_context(f"/?cid={CID}"):
        login_user(User.query.filter(User.id == 1).first())
        info = export_case_json_for_report(CID)
info.update(doc_id="TEST", user="administrator", date="2026-01-01")
env = IrisJinjaEnv(); env.filters = app.jinja_env.filters
print(env.from_string(open("/tmp/tpl.md").read()).render(info)[:2000])
EOF
```

Le contexte de requête et le `login_user` sont obligatoires : `export_case_iocs_json`
passe par un contrôle de permission qui lit `request.args`.
