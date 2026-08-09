{#-
  Rapport d'investigation d'incident — Aura-SOC / DFIR-IRIS (type Investigation, Markdown).

  Adapté depuis Rapport-Investigation-IRIS.docx (page de garde + structure en
  7 sections + annexe preuves). Le .docx d'origine utilisait des variables
  inventées (case.case_id sans vérif, timeline_events, notes[].title/content,
  ioc.ioc_type en chaîne, asset.asset_type, task.task_assignee, evidences[].
  file_description) et une pseudo-syntaxe {%p%}/{%tr%} qui n'existe pas dans
  Jinja — rien de tout ça n'aurait rendu. Réécrit ici sur le contexte réel
  exposé par IRIS (app/datamgmt/reporter/report_db.py,
  export_case_json_for_report, v2.4.27) et les macros de
  incident-technique-fr.md.

  Pièges vérifiés sur IRIS v2.4.27 (voir report-templates/README.md) :
  - dates de `case`/`notes` = STR (marshmallow) ; dates de
    timeline/tasks/assets/evidences = datetime → macro `dt()`.
  - `evidences` n'exporte PAS de description (full_log/JSON restent dans
    IRIS, non atteignables ici) : colonne retirée de l'annexe preuves.
  - environnement Jinja sandboxé (IrisJinjaEnv) : pas d'attribut dunder, pas
    d'appel de type ; `.strftime()` sur un datetime reste permis.
  - `notes` est une liste plate ; le répertoire est dans note.directory.name.
  - tableaux Markdown : filtrer `\n` et échapper `|` → macro `cell()`.
-#}
{%- macro dt(v, fmt='%Y-%m-%d %H:%M') -%}
{%- if not v %}—{% elif v.strftime is defined %}{{ v.strftime(fmt) }}{% else %}{{ v }}{% endif -%}
{%- endmacro -%}
{%- macro corps(v) -%}
{{ ('\n' ~ (v | string)) | replace('\n#### ', '\n###### ') | replace('\n### ', '\n#####  ') | replace('\n## ', '\n#### ') | replace('\n# ', '\n### ') }}
{%- endmacro -%}
{%- macro cell(v, n=110) -%}
{{ (v if v else '—') | string | replace('\n', ' ') | replace('\r', ' ') | replace('|', '\\|') | truncate(n, true, '…') }}
{%- endmacro -%}

# AURA · SOC — RAPPORT D'INVESTIGATION D'INCIDENT

**{{ case.name }}**

| | |
|---|---|
| **Identifiant du dossier** | #{{ case.case_id }} |
| **Classification** | {{ case.classification.name if case.classification else '—' }} |
| **Sévérité / criticité** | {{ case.severity.severity_name if case.severity else '—' }} |
| **Date d'ouverture** | {{ dt(case.open_date) }} |
| **Date de clôture** | {{ dt(case.close_date) if case.close_date else 'Investigation en cours' }} |
| **Étiquettes** | {{ case.tags | map(attribute='tag_title') | join(', ') if case.tags else '—' }} |

**CONFIDENTIEL** — Document réservé à l'équipe de réponse à incident (CSIRT / SOC). Ne pas diffuser sans autorisation.

## 1. Résumé exécutif

Ce rapport présente les constats, l'analyse et les actions engagées dans le cadre de l'investigation du dossier référencé en page de garde. Il est généré automatiquement à partir des données consignées dans DFIR-IRIS.

Sévérité évaluée : {{ case.severity.severity_name if case.severity else 'non renseignée' }} — Classification : {{ case.classification.name if case.classification else 'non renseignée' }}.

### Contexte du dossier

{{ case.description if case.description else "_Aucune description synthétique n'a été renseignée pour ce dossier._" }}

## 2. Chronologie de l'incident

{% if timeline -%}
Séquence des événements marquants reconstituée durant l'investigation :

| Horodatage | Événement | Détails |
|---|---|---|
{% for e in timeline -%}
| {{ dt(e.event_date, '%Y-%m-%d %H:%M:%S') }} | {{ cell(e.event_title, 90) }} | {{ cell(e.event_content, 160) }} |
{% endfor %}
{%- else -%}
_Aucun événement de chronologie n'a été enregistré pour ce dossier._
{%- endif %}

## 3. Analyse technique détaillée

{% if notes -%}
{% for note in notes %}
### {{ note.note_title }}

> Répertoire : {{ note.directory.name if note.directory else '—' }} — mise à jour {{ dt(note.note_lastupdate) }}

{{ corps(note.note_content) if note.note_content else "_Contenu non renseigné._" }}

{% endfor -%}
{%- else -%}
_Aucune note d'analyse technique n'a été consignée pour ce dossier._
{%- endif %}

## 4. Indicateurs de compromission (IOC)

{% if iocs -%}
Indicateurs identifiés au cours de l'investigation. Les valeurs ci-dessous sont fournies à des fins de détection et de blocage.

| Type | Valeur | Description |
|---|---|---|
{% for i in iocs | sort(attribute='ioc_type.type_name') -%}
| {{ cell(i.ioc_type.type_name if i.ioc_type else '—', 25) }} | `{{ cell(i.ioc_value, 120) }}` | {{ cell(i.ioc_description, 140) }} |
{% endfor %}
{%- else -%}
_Aucun indicateur de compromission n'a été identifié pour ce dossier._
{%- endif %}

## 5. Actifs impactés

{% if assets -%}
Systèmes et actifs entrant dans le périmètre de l'incident :

| Actif | Type | Adresse IP | Statut |
|---|---|---|---|
{% for a in assets -%}
| **{{ cell(a.asset_name, 40) }}** | {{ cell(a.type, 30) }} | {{ cell(a.asset_ip, 40) }} | {{ cell(a.asset_compromise_status, 20) }} |
{% endfor %}
{%- else -%}
_Aucun actif n'a été rattaché à ce dossier._
{%- endif %}

## 6. Actions de remédiation

{% if tasks -%}
Tâches de confinement, d'éradication et de rétablissement suivies dans le dossier :

| Tâche | Statut | Assigné à | Description |
|---|---|---|---|
{% for t in tasks | sort(attribute='task_open_date') -%}
| **{{ cell(t.task_title, 60) }}** | {{ cell(t.task_status, 20) }} | {{ cell(t.task_assignees | map(attribute='user_name') | join(', ') if t.task_assignees else 'Non assignée', 40) }} | {{ cell(t.task_description, 160) }} |
{% endfor %}

Rappel : les tâches posées par le soc-agent tracent des remédiations **déjà exécutées** automatiquement (XDR autonome). Une tâche passée en `Canceled` déclenche l'annulation de la remédiation correspondante au cycle suivant.
{%- else -%}
_Aucune action de remédiation n'a encore été enregistrée pour ce dossier._
{%- endif %}

## 7. Conclusion et recommandations

### Synthèse de l'investigation

_« À compléter par l'analyste : rappeler l'origine de l'incident, l'étendue de la compromission, l'impact métier constaté et l'état de résolution. »_

### Recommandations

- _« À compléter : mesures correctives prioritaires. »_
- _« À compléter : renforcements de détection et de journalisation. »_
- _« À compléter : actions organisationnelles et de sensibilisation. »_

## Annexe A — Preuves collectées

{% if evidences -%}
Inventaire des éléments de preuve versés au dossier ({{ evidences | length }} pièce(s)). La description détaillée (full_log, JSON brut, deep-link Discover) reste consultable dans l'onglet Evidence du case IRIS — non exportable dans ce rapport.

| Élément de preuve | Ajoutée le | Empreinte (hash) |
|---|---|---|
{% for ev in evidences | sort(attribute='date_added') -%}
| {{ cell(ev.filename, 100) }} | {{ dt(ev.date_added) }} | `{{ ev.file_hash }}` |
{% endfor %}
{%- else -%}
_Aucun élément de preuve n'a été versé au dossier._
{%- endif %}

---

Rapport généré depuis DFIR-IRIS le {{ dt(export_date) }} UTC — case #{{ case.case_id }} — document `{{ doc_id }}`.
Chaîne Aura-SOC : détection Wazuh → corrélation soc-agent → triage LLM → remédiation autonome. Les verdicts d'analyse sont produits par un modèle de langage et ne constituent pas une frontière de sécurité : les garde-fous sont déterministes (code + scripts d'active response).
