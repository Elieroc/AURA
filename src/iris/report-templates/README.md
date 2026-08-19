# Templates de rapport IRIS

Templates Jinja2 rendus par DFIR-IRIS depuis un case (bouton **Generate report**
→ type *Investigation*). À ne pas confondre avec les *case templates* d'IRIS,
qui pré-remplissent un case à sa création — le soc-agent construit ses cases en
code (`src/ai/soc_agent/iris.py`), il n'en utilise aucun.

| Fichier | Type | Langue | Contenu |
|---|---|---|---|
| `incident-technique-fr.md` | Investigation | FR | Rapport DFIR complet : synthèse, note d'analyse IA, machines, exposition aux vulnérabilités, IOC, chronologie, remédiations, preuves |
| `rapport-investigation-fr.docx` | Investigation | FR | Page de garde avec logo AURA·SOC, résumé exécutif, chronologie, analyse technique, IOC, actifs, remédiations, conclusion/recommandations à compléter par l'analyste, annexe preuves |
| `data-leak-fr.md` | Investigation | FR | Rapport de veille data-leak (cases posés par `soc_agent.data_leak`) : compte exposé, détail des fuites XposedOrNot, IOC email. Volontairement SANS section machines/timeline/exposition — ces cases documentent une personne, pas une machine du parc |

Le second template est un **.docx Word** (pas du Markdown) : IRIS accepte
`md`, `html`, `doc`, `docx` en pièce de template
(`manage_templates_routes.py: ALLOWED_EXTENSIONS`) et bascule sur un moteur
de rendu différent selon l'extension — `IrisMakeDocReport` /
`docx_generator.DocxGenerator` (basé sur **docxtpl**) pour `.docx`, contre
`IrisMakeMdReport` (Jinja pur, cf. `IrisJinjaEnv` ci-dessous) pour `.md`/`.html`.
Choisir le format quand la mise en forme Word (logo, couleurs, styles) doit
être conservée ; le contexte Jinja exposé est le même dans les deux cas
(`export_case_json`/`export_case_json_for_report`, mêmes noms de champs).

## Déploiement

```bash
IRIS_URL=https://127.0.0.1:8443 \
IRIS_API_KEY=<clé d'un compte server_administrator> \
  ../scripts/deploy-report-template.sh incident-technique-fr.md
# ou, pour le second template (docx) :
  ../scripts/deploy-report-template.sh rapport-investigation-fr.docx "Aura-SOC — Rapport d'investigation d'incident (FR)"
# ou, pour le rapport de veille data-leak (nom de fichier et description
# dédiés, sinon le script réutilise ceux du rapport d'incident technique) :
  FORMAT_NOM="Aura-SOC_veille-data-leak_%code_name%" \
  DESCRIPTION="Rapport de veille data-leak : compte exposé, détail des fuites XposedOrNot, IOC email." \
  ../scripts/deploy-report-template.sh data-leak-fr.md "Aura-SOC — Veille data-leak (FR)"
```

Le script supprime l'entrée de même nom avant de recréer : IRIS n'a **pas**
d'endpoint de mise à jour, `add` empile des doublons. L'id du template change
donc à chaque déploiement — ne pas le câbler en dur ailleurs. Fonctionne tel
quel pour un `.docx` (`curl -F file=@...`), le script ne dépend pas du format.

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
- **`notes` est une liste plate**, le répertoire est dans `note.directory.name`.
  Le soc-agent en utilise deux, et le template les traite séparément :
  `Analyse IA` (récit produit par le modèle → section 2) et `Exposition`
  (exposition aux vulnérabilités, calculée en Python depuis l'inventaire Wazuh,
  sans LLM → section 4). Toute note d'un autre répertoire retombe dans la
  section « Notes complémentaires ». **En ajouter un troisième impose de
  l'exclure explicitement de `notes_autres`**, sinon il apparaîtra deux fois.
- **Markdown en tableau** : filtrer les `\n` et échapper les `|`, sinon la
  table se disloque (macro `cell()`).
- **Nom de fichier généré** : `%case_name%` est évité dans le format de nommage,
  un `/` dans un titre de case casserait le chemin d'écriture.
- **`rapport-investigation-fr.docx`** est un gabarit Word édité par un
  non-développeur avec des noms de variables inventés (`timeline_events`,
  `note.title`/`content`, `ioc.ioc_type` en chaîne, `asset.asset_type`,
  `task.task_assignee`, `evidences[].file_description` — qui n'existe pas,
  cf. piège evidences ci-dessus). Corrigés sur les vrais noms de champs
  (`timeline`, `note.note_title`/`note_content`, `ioc.ioc_type.type_name`,
  `asset.type`, `task.task_assignees[]`, `asset.asset_compromise_status` en
  chaîne `"Compromised"/"Not Compromised"/…`, jamais un booléen).
- **Piège docxtpl `{%tr for%}` / `{%tr endfor%}` dans la même ligne de
  tableau.** Le patch XML de docxtpl (`docxtpl/__init__.py: patch_xml`, y in
  `['tr','tc','p','r']`) repère un tag `{%tr ...%}` puis remplace **toute la
  ligne** `<w:tr>…</w:tr>` qui le contient par le seul tag nu — si `for` et
  `endfor` sont dans la même ligne (avec les cellules de données entre eux,
  comme dans le .docx d'origine), la ligne du `for` avale aussi le `endfor` :
  rendu en échec silencieux (`TemplateSyntaxError: Encountered unknown tag
  'endfor'`) ou tableau vidé sans erreur. Reproduit isolément avec docxtpl
  0.10.0 (celui vendu dans `iris-app`). **Fix** : structurer chaque boucle de
  tableau sur **3 lignes** — une ligne marqueur portant seul `{%tr for … %}`
  (gridSpan sur toutes les colonnes, bordures nil, hauteur ~1pt), la ligne de
  données sans aucun tag `tr`, puis une ligne marqueur `{%tr endfor %}`
  identique. Les tags `{%p if/else/endif%}` seuls dans leur propre paragraphe
  n'ont pas ce problème (confirmé) ; un `{% if %}`/`{% else %}`/`{% endif %}`
  simple (sans préfixe y) mélangé à du texte dans la même cellule est
  également sans risque, seul le préfixe `tr`/`p` déclenche le découpage XML.

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

Pour un template `.docx`, le moteur est différent (`DocxGenerator` /
`export_case_json`, pas `IrisJinjaEnv` / `export_case_json_for_report`) :

```bash
docker cp mon-template.docx iris-app:/tmp/tpl.docx
docker exec -e PYTHONPATH=/iriswebapp iris-app python - <<'EOF'
from app import app
from app.models.authorization import User
from flask_login import login_user
from app.datamgmt.reporter.report_db import export_case_json
from app.iris_engine.reporter.ImageHandler import ImageHandler
from docx_generator.docx_generator import DocxGenerator
import tempfile, os

CID = 197
with app.app_context():
    with app.test_request_context(f"/?cid={CID}"):
        login_user(User.query.filter(User.id == 1).first())
        info = export_case_json(CID)
info.update(doc_id="TEST", user="administrator", date="2026-01-01")

tmp = tempfile.mkdtemp()
out = os.path.join(tmp, "out.docx")
gen = DocxGenerator(image_handler=ImageHandler(template=None, base_path="/"))
gen.generate_docx("/", "/tmp/tpl.docx", info, out)
print("OK ->", out, os.path.getsize(out))
EOF
```

Une `RenderingError` avec un `.strftime` ou un attribut manquant pointe vers
un mauvais nom de champ ; un `TemplateSyntaxError` sur `endfor`/`else`/`endif`
pointe presque toujours vers le piège `{%tr%}` décrit plus haut.
